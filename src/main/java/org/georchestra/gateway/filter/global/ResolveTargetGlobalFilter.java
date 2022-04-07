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
package org.georchestra.gateway.filter.global;

import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;

import java.net.URI;
import java.util.Objects;

import org.georchestra.gateway.model.GatewayConfigProperties;
import org.georchestra.gateway.model.GeorchestraTargetConfig;
import org.georchestra.gateway.model.Service;
import org.georchestra.gateway.security.ResolveGeorchestraUserGlobalFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.RouteToRequestUrlFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.core.Ordered;
import org.springframework.web.server.ServerWebExchange;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * A {@link GlobalFilter} that resolves the {@link GeorchestraTargetConfig
 * configuration} for the request's matched {@link Route} and
 * {@link GeorchestraTargetConfig#setTarget stores} it to be
 * {@link GeorchestraTargetConfig#getTarget acquired} by non-global filters as
 * needed.
 */
@RequiredArgsConstructor
@Slf4j
public class ResolveTargetGlobalFilter implements GlobalFilter, Ordered {

    public static final int ORDER = ResolveGeorchestraUserGlobalFilter.ORDER + 1;

    private final @NonNull GatewayConfigProperties config;

    /**
     * @return a lower precedence than {@link RouteToRequestUrlFilter}'s, in order
     *         to make sure the matched {@link Route} has been set as a
     *         {@link ServerWebExchange#getAttributes attribute} when
     *         {@link #filter} is called.
     */
    public @Override int getOrder() {
        return ResolveTargetGlobalFilter.ORDER;
    }

    /**
     * Resolves the matched {@link Route} and its corresponding
     * {@link GeorchestraTargetConfig}, if possible, and proceeds with the filter
     * chain.
     */
    public @Override Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        Route route = (Route) exchange.getAttributes().get(GATEWAY_ROUTE_ATTR);
        if (null == route) {
            log.info("Requested URI didn't match any Route, geOrchestra target resolution ignored.");
        } else {
            GeorchestraTargetConfig config = resolveTarget(route);
            log.debug("Storing geOrchestra target config for Route {} request context", route.getId());
            GeorchestraTargetConfig.setTarget(exchange, config);
        }
        return chain.filter(exchange);
    }

    private @NonNull GeorchestraTargetConfig resolveTarget(@NonNull Route route) {

        GeorchestraTargetConfig target = new GeorchestraTargetConfig().headers(config.getDefaultHeaders())
                .accessRules(config.getGlobalAccessRules());

        final URI routeURI = route.getUri();

        for (Service service : config.getServices().values()) {
            var serviceURI = service.getTarget();
            if (Objects.equals(routeURI, serviceURI)) {
                if (!service.getAccessRules().isEmpty())
                    target.accessRules(service.getAccessRules());
                if (service.getHeaders().isPresent())
                    target.headers(service.getHeaders().get());
                break;
            }
        }
        return target;
    }

}