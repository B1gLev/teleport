/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package auth

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/utils"
)

// GitLab support reuses the "github" auth connector kind. A connector is
// treated as a GitLab connector when it carries the label provider=gitlab and
// its endpoint_url points at the GitLab instance, for example:
//
//	kind: github
//	version: v3
//	metadata:
//	  name: gitlab
//	  labels:
//	    provider: gitlab
//	spec:
//	  endpoint_url: https://gitlab.example.com
//	  ...
//
// GitLab groups are mapped onto the GitHub organization/team model: the
// organization is the top-level group and the team is the full group path
// (for example "acme/infra" in organization "acme"). Only direct group
// memberships are reported by GitLab, ancestors are not implied.
const (
	gitlabProviderLabel = "provider"
	gitlabProviderValue = "gitlab"

	gitlabAuthPath     = "oauth/authorize"
	gitlabTokenPath    = "oauth/token"
	gitlabUserinfoPath = "oauth/userinfo"
)

// GitlabScopes is the list of scopes requested during the GitLab OAuth2 flow.
// "openid" returns the user ID and the groups_direct claim, "profile" adds
// the username (nickname claim).
var GitlabScopes = []string{"openid", "profile"}

// isGitlabConnector returns true if the connector is labelled as a GitLab one.
func isGitlabConnector(c types.GithubConnector) bool {
	return c.GetMetadata().Labels[gitlabProviderLabel] == gitlabProviderValue
}

// validateGitlabConnector makes sure a GitLab labelled connector has a usable
// endpoint URL. It is a no-op for regular GitHub connectors.
func validateGitlabConnector(c types.GithubConnector) error {
	if !isGitlabConnector(c) {
		return nil
	}
	base := c.GetEndpointURL()
	if base == types.GithubURL {
		return trace.BadParameter("GitLab connector %q requires endpoint_url to be set to the URL of the GitLab instance", c.GetName())
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return trace.BadParameter("GitLab connector %q: endpoint_url must be an absolute https:// URL", c.GetName())
	}
	return nil
}

// gitlabUserinfo is the subset of the GitLab OpenID Connect userinfo response
// that is used to build Teleport claims.
type gitlabUserinfo struct {
	Sub               string   `json:"sub"`
	Nickname          string   `json:"nickname"`
	PreferredUsername string   `json:"preferred_username"`
	GroupsDirect      []string `json:"groups_direct"`
}

// getGitlabUserAndTeams exchanges the authorization code for a token, queries
// the GitLab userinfo endpoint and converts the result to the structures the
// GitHub code path works with.
func (a *Server) getGitlabUserAndTeams(
	ctx context.Context,
	connector types.GithubConnector,
	code string,
	diagCtx *SSODiagContext,
	logger *slog.Logger,
) (*GithubUserResponse, []GithubTeamResponse, error) {
	config := newGithubOAuth2Config(connector)

	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, nil, trace.Wrap(err, "Requesting GitLab OAuth2 token failed.")
	}

	// GitLab normally echoes the granted scopes, but do not fail if it does not.
	scope, _ := token.Extra("scope").(string)
	diagCtx.Info.GithubTokenInfo = &types.GithubTokenInfo{
		TokenType: token.TokenType,
		Expires:   token.ExpiresIn,
		Scope:     scope,
	}
	logger.DebugContext(ctx, "Obtained GitLab OAuth2 token",
		"type", token.TokenType, "expires", token.ExpiresIn, "scope", scope)

	ui, err := fetchGitlabUserinfo(ctx, connector.GetEndpointURL(), token.AccessToken)
	if err != nil {
		return nil, nil, trace.Wrap(err, "failed to query GitLab user info")
	}

	user, teams, err := gitlabUserAndTeams(ui)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	logger.DebugContext(ctx, "Retrieved groups for GitLab user.",
		"num_groups", len(teams), "gitlab_user", user.Login)
	return user, teams, nil
}

func fetchGitlabUserinfo(ctx context.Context, baseURL, accessToken string) (*gitlabUserinfo, error) {
	client, err := defaults.HTTPClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ctx, cancel := context.WithTimeout(ctx, defaults.HTTPRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(baseURL, "/")+"/"+gitlabUserinfoPath, nil)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer resp.Body.Close()

	body, err := utils.ReadAtMost(resp.Body, teleport.MaxHTTPResponseSize)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, trace.AccessDenied("bad response from GitLab userinfo endpoint: %v", resp.StatusCode)
	}

	var ui gitlabUserinfo
	if err := json.Unmarshal(body, &ui); err != nil {
		return nil, trace.Wrap(err)
	}
	return &ui, nil
}

// gitlabUserAndTeams converts a GitLab userinfo response to the user and team
// structures used by populateGithubClaims.
func gitlabUserAndTeams(ui *gitlabUserinfo) (*GithubUserResponse, []GithubTeamResponse, error) {
	username := ui.Nickname
	if username == "" {
		username = ui.PreferredUsername
	}
	if username == "" {
		return nil, nil, trace.BadParameter("GitLab userinfo has no username, was the profile scope granted?")
	}
	id, err := strconv.ParseInt(ui.Sub, 10, 64)
	if err != nil {
		return nil, nil, trace.BadParameter("GitLab userinfo has an invalid subject %q", ui.Sub)
	}

	teams := make([]GithubTeamResponse, 0, len(ui.GroupsDirect))
	for _, g := range ui.GroupsDirect {
		g = strings.Trim(g, "/")
		if g == "" {
			continue
		}
		org, _, _ := strings.Cut(g, "/")
		teams = append(teams, GithubTeamResponse{
			Name: g,
			Slug: g,
			Org:  GithubOrgResponse{Login: org},
		})
	}
	return &GithubUserResponse{Login: username, ID: id}, teams, nil
}
