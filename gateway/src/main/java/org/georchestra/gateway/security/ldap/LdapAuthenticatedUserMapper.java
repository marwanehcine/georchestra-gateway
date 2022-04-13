/*
 * Copyright (C) 2022 by the geOrchestra PSC
 *
 * This file is part of geOrchestra.
 *
 * geOrchestra is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * geOrchestra is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * geOrchestra.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.georchestra.gateway.security.ldap;

import java.util.Optional;

import org.georchestra.gateway.security.BasicAuthenticatedUserMapper;
import org.georchestra.gateway.security.GeorchestraUserMapperExtension;
import org.georchestra.security.api.OrganizationsApi;
import org.georchestra.security.api.RolesApi;
import org.georchestra.security.api.UsersApi;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 *
 */
@RequiredArgsConstructor
public class LdapAuthenticatedUserMapper implements GeorchestraUserMapperExtension {

    private final @NonNull UsersApi users;
    private final @NonNull OrganizationsApi organizations;
    private final @NonNull RolesApi roles;

    @Override
    public Optional<GeorchestraUser> resolve(Authentication authToken) {
        return Optional.ofNullable(authToken)//
                .filter(UsernamePasswordAuthenticationToken.class::isInstance)
                .map(UsernamePasswordAuthenticationToken.class::cast)//
                .filter(token -> token.getPrincipal() instanceof LdapUserDetails)//
                .flatMap(this::map);
    }

    Optional<GeorchestraUser> map(UsernamePasswordAuthenticationToken token) {
        final String username = token.getName();
        return users.findByUsername(username);
    }

    /**
     * A higher precedence order than {@link BasicAuthenticatedUserMapper}
     */
    public @Override int getOrder() {
        return BasicAuthenticatedUserMapper.ORDER - 1;
    }

}
