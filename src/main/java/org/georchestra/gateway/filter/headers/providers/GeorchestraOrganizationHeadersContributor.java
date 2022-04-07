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
package org.georchestra.gateway.filter.headers.providers;

import java.util.Optional;
import java.util.function.Consumer;

import org.georchestra.gateway.filter.headers.HeaderContributor;
import org.georchestra.gateway.model.GeorchestraOrganization;
import org.georchestra.gateway.model.GeorchestraTargetConfig;
import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;

public class GeorchestraOrganizationHeadersContributor extends HeaderContributor {

    public @Override Consumer<HttpHeaders> prepare(ServerWebExchange exchange) {
        return headers -> {
            GeorchestraTargetConfig.getTarget(exchange)//
                    .map(GeorchestraTargetConfig::headers)//
                    .ifPresent(mappings -> {
                        Optional<GeorchestraOrganization> org = GeorchestraOrganization.resolve(exchange);
                        add(headers, "sec-orgname", mappings.getOrgname(), org.map(GeorchestraOrganization::getName));
                    });
        };
    }
}
