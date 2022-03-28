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
package org.georchestra.gateway.security;

import java.util.List;

import org.georchestra.gateway.model.GatewayConfigProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import lombok.extern.slf4j.Slf4j;

@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
@EnableConfigurationProperties(GatewayConfigProperties.class)
@Slf4j(topic = "org.georchestra.gateway.security")
public class GatewaySecurityConfiguration {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http, GatewayConfigProperties config,
            List<ServerHttpSecurityCustomizer> customizers) throws Exception {

        // disable csrf and cors or the websocket connection gets a 403 Forbidden.
        // Revisit.
        http.csrf().disable().cors().disable();

        customizers.forEach(customizer -> {
            log.debug("Applying security customizer " + customizer.getName());
            customizer.customize(http);
        });

//		http.authorizeExchange()//
//				.pathMatchers("/", "/header/**").permitAll()//
//				.pathMatchers("/ws/**").permitAll()//
//				.pathMatchers("/**").authenticated();

        return http.build();
    }
}
