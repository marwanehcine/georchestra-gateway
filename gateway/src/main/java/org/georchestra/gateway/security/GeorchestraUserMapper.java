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

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.georchestra.gateway.model.GeorchestraUsers;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.security.core.Authentication;
import org.springframework.web.server.ServerWebExchange;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Relies on the provided {@link GeorchestraUserMapperExtension}s to map an
 * {@link Authentication} to a {@link GeorchestraUsers}.
 */
@RequiredArgsConstructor
public class GeorchestraUserMapper {

    static final String GEORCHESTRA_USER_KEY = GeorchestraUser.class.getCanonicalName();

    private final @NonNull List<GeorchestraUserMapperExtension> resolvers;

    public Optional<GeorchestraUser> resolve(Authentication authToken) {
        return resolvers.stream().map(resolver -> resolver.resolve(authToken)).filter(Optional::isPresent)
                .map(Optional::get).findFirst();
    }

    public static ServerWebExchange store(@NonNull ServerWebExchange exchange, GeorchestraUser user) {
        Map<String, Object> attributes = exchange.getAttributes();
        if (user == null) {
            attributes.remove(GEORCHESTRA_USER_KEY);
        } else {
            attributes.put(GEORCHESTRA_USER_KEY, user);
        }
        return exchange;
    }

}