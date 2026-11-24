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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
)

func TestGitlabUserAndTeams(t *testing.T) {
	user, teams, err := gitlabUserAndTeams(&gitlabUserinfo{
		Sub:          "42",
		Nickname:     "alice",
		GroupsDirect: []string{"acme", "acme/infra/ops", "/other/", ""},
	})
	require.NoError(t, err)
	require.Equal(t, "alice", user.Login)
	require.EqualValues(t, 42, user.ID)

	claims, err := populateGithubClaims(user, teams)
	require.NoError(t, err)
	require.Equal(t, "alice", claims.Username)
	require.Equal(t, "42", claims.UserID)
	require.Equal(t, map[string][]string{
		"acme":  {"acme", "acme/infra/ops"},
		"other": {"other"},
	}, claims.OrganizationToTeams)

	connector, err := types.NewGithubConnector("gitlab", types.GithubConnectorSpecV3{
		TeamsToRoles: []types.TeamRolesMapping{
			{Organization: "acme", Team: "acme/infra/ops", Roles: []string{"access"}},
		},
	})
	require.NoError(t, err)
	roles, _, _ := connector.MapClaims(*claims)
	require.Equal(t, []string{"access"}, roles)
}

func TestGitlabUserAndTeamsErrors(t *testing.T) {
	_, _, err := gitlabUserAndTeams(&gitlabUserinfo{Sub: "1"})
	require.Error(t, err, "missing username")

	_, _, err = gitlabUserAndTeams(&gitlabUserinfo{Sub: "abc", Nickname: "bob"})
	require.Error(t, err, "non-numeric subject")
}

func TestValidateGitlabConnector(t *testing.T) {
	newConn := func(labels map[string]string, endpoint string) types.GithubConnector {
		c, err := types.NewGithubConnector("c", types.GithubConnectorSpecV3{EndpointURL: endpoint})
		require.NoError(t, err)
		md := c.GetMetadata()
		md.Labels = labels
		c.SetMetadata(md)
		return c
	}
	gitlab := map[string]string{"provider": "gitlab"}

	require.NoError(t, validateGitlabConnector(newConn(nil, "")), "plain GitHub connectors are untouched")
	require.Error(t, validateGitlabConnector(newConn(gitlab, "")), "endpoint_url is required")
	require.Error(t, validateGitlabConnector(newConn(gitlab, "http://gitlab.example.com")), "https only")
	require.NoError(t, validateGitlabConnector(newConn(gitlab, "https://gitlab.example.com/")))
}
