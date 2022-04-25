/*
 * Copyright (C) 2021 by the geOrchestra PSC
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

import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import org.georchestra.gateway.filter.headers.providers.GeorchestraOrganizationHeadersContributor;
import org.georchestra.gateway.filter.headers.providers.GeorchestraUserHeadersContributor;
import org.georchestra.gateway.filter.headers.providers.SecProxyHeaderContributor;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.web.server.ServerWebExchange;

import lombok.extern.slf4j.Slf4j;

/**
 * Extension point to aid {@link AddSecHeadersGatewayFilterFactory} in appending
 * the required HTTP request headers to proxied requests.
 * <p>
 * Beans of this type are strategy objects that contribute zero or more HTTP
 * request headers to be appended to proxied requests to back-end services.
 * 
 * @see SecProxyHeaderContributor
 * @see GeorchestraUserHeadersContributor
 * @see GeorchestraOrganizationHeadersContributor
 */
@Slf4j
public abstract class HeaderContributor implements Ordered {

    /**
     * Prepare a header contributor for the given HTTP request-response interaction.
     * <p>
     * The returned consumer will {@link HttpHeaders#set(String, String) set} or
     * {@link HttpHeaders#add(String, String) add} whatever request headers are
     * appropriate for the backend service.
     */
    public abstract Consumer<HttpHeaders> prepare(ServerWebExchange exchange);

    /**
     * {@inheritDoc}
     * 
     * @return {@code 0} as default order, implementations should override as needed
     *         in case they need to apply their customizations to
     *         {@link ServerHttpSecurity} in a specific order.
     * @see Ordered#HIGHEST_PRECEDENCE
     * @see Ordered#LOWEST_PRECEDENCE
     */
    public @Override int getOrder() {
        return 0;
    }

    protected void add(HttpHeaders target, String header, Optional<Boolean> enabled, Optional<String> value) {
        add(target, header, enabled, value.orElse(null));
    }

    protected void add(HttpHeaders target, String header, Optional<Boolean> enabled, List<String> values) {
        add(target, header, enabled, values.stream().collect(Collectors.joining(";")));
    }

    protected void add(HttpHeaders target, String header, Optional<Boolean> enabled, String value) {
        if (enabled.orElse(Boolean.FALSE).booleanValue()) {
            if (null == value) {
                log.debug("Value for header {} is not present", header);
            } else {
                log.debug("Appending header {}: {}", header, value);
                target.add(header, value);
            }
        } else {
            log.debug("Header {} is not enabled", header);
        }
    }

}
