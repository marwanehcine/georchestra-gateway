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
package org.georchestra.gateway.security.accessrules;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.georchestra.gateway.model.GatewayConfigProperties;
import org.georchestra.gateway.model.RoleBasedAccessRule;
import org.georchestra.gateway.security.ServerHttpSecurityCustomizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec;
import org.springframework.security.config.web.server.ServerHttpSecurity.AuthorizeExchangeSpec.Access;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j(topic = "org.georchestra.gateway.config.security.accessrules")
public class AccessRulesCustomizer implements ServerHttpSecurityCustomizer {

    private final GatewayConfigProperties config;

    @Override
    public void customize(ServerHttpSecurity http) {
        log.info("Configuring proxied applications access rules...");

        AuthorizeExchangeSpec authorizeExchange = http.authorizeExchange();

        log.info("Applying global access rules...");
        apply(authorizeExchange, config.getGlobalAccessRules());

        config.getServices().forEach((name, service) -> {
            log.info("Applying access rules for backend service '{}'", name);
            apply(authorizeExchange, service.getAccessRules());
        });
    }

    private void apply(AuthorizeExchangeSpec authorizeExchange, List<RoleBasedAccessRule> accessRules) {
        if (accessRules == null || accessRules.isEmpty()) {
            log.info("No access rules found.");
            return;
        }
        for (RoleBasedAccessRule rule : accessRules) {
            apply(authorizeExchange, rule);
        }
    }

    private void apply(AuthorizeExchangeSpec authorizeExchange, RoleBasedAccessRule rule) {
        List<String> antPatterns = rule.getInterceptUrl();
        boolean anonymous = rule.isAnonymous();
        List<String> allowedRoles = rule.getAllowedRoles() == null ? List.of() : rule.getAllowedRoles();
        Access access = authorizeExchange.pathMatchers(antPatterns.toArray(String[]::new));
        if (anonymous) {
            log.info("Access rule: {} anonymous", antPatterns);
            access.permitAll();
        } else if (!allowedRoles.isEmpty()) {
            String[] roles = allowedRoles.stream().map(this::ensureRolePrefix).toArray(String[]::new);
            log.info("Access rule: {} has any role: {}", antPatterns,
                    Stream.of(roles).collect(Collectors.joining(",")));
            access.hasAnyAuthority(roles);
        } else {
            log.warn(
                    "The following intercepted URL's don't have any access rule defined. Defaulting to 'authenticated': {}",
                    antPatterns);
            access.authenticated();
        }
    }

    private String ensureRolePrefix(@NonNull String roleName) {
        return roleName.startsWith("ROLE_") ? roleName : ("ROLE_" + roleName);
    }
}
