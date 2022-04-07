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

import java.util.Set;

import org.georchestra.gateway.filter.global.ResolveTargetGlobalFilter;
import org.georchestra.gateway.model.GeorchestraTargetConfig;
import org.georchestra.gateway.model.GeorchestraUser;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.filter.RouteToRequestUrlFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.server.ServerWebExchange;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * A {@link GlobalFilter} that resolves the {@link GeorchestraUser} from the
 * request's {@link Authentication} so it can be {@link GeorchestraUser#resolve
 * retrieved} down the road during the filter chain.
 * 
 * @see GeorchestraUserMapper
 */
@RequiredArgsConstructor
@Slf4j
public class ResolveGeorchestraUserGlobalFilter implements GlobalFilter, Ordered {

	public static final int ORDER = RouteToRequestUrlFilter.ROUTE_TO_URL_FILTER_ORDER + 1;

	private static final Authentication NONE = new AnonymousAuthenticationToken("none", new Object(),
			Set.of(new SimpleGrantedAuthority("UNAUTHENTICATED")));

	private final @NonNull GeorchestraUserMapper resolver;

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

		return exchange.getPrincipal()//
				.doOnNext(p -> log.debug("resolving user from {}", p.getClass().getName()))//
				.filter(Authentication.class::isInstance)//
				.map(Authentication.class::cast)//
				.defaultIfEmpty(NONE)//
				.map(resolver::resolve).map(user -> {
					return GeorchestraUser.store(exchange, user.orElse(null));
				}).flatMap(chain::filter);
	}

}