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
package org.georchestra.gateway.filter.headers;

import java.net.URI;
import java.util.function.Consumer;

import org.georchestra.gateway.config.GatewayConfigProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;

public class StandardSecurityHeadersProvider implements HeaderProvider {

    private @Autowired GatewayConfigProperties config;

    @Override
    public Consumer<HttpHeaders> prepare(ServerWebExchange exchange) {
        return headers -> {
            URI uri = exchange.getRequest().getURI();
            String path = uri.getPath();
            GatewayConfigProperties c = config;
            System.err.println(uri);
        };
    }

}
