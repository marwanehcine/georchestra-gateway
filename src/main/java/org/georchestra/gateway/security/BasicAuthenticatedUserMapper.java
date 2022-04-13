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

package org.georchestra.gateway.security;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

import org.georchestra.gateway.model.GeorchestraUsers;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * @author groldan
 *
 */
public class BasicAuthenticatedUserMapper implements GeorchestraUserMapperExtension {

    public static final int ORDER = 0;

    @Override
    public Optional<GeorchestraUser> resolve(Authentication authToken) {
        return Optional.ofNullable(authToken)//
                .filter(UsernamePasswordAuthenticationToken.class::isInstance)
                .map(UsernamePasswordAuthenticationToken.class::cast)//
                .flatMap(this::map);
    }

    Optional<GeorchestraUser> map(UsernamePasswordAuthenticationToken token) {
        GeorchestraUser user = new GeorchestraUser();

        Collection<GrantedAuthority> authorities = token.getAuthorities();
        List<String> roles = authorities.stream().map(GrantedAuthority::getAuthority).toList();
        String name = token.getName();

        Object principal = token.getPrincipal();
        Object details = token.getDetails();

        user.setUsername(name);
        user.setRoles(roles);
        return Optional.of(user);
    }

    public @Override int getOrder() {
        return ORDER;
    }
}
