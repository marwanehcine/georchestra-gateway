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

package org.georchestra.gateway.security.oauth2;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import org.georchestra.gateway.model.GeorchestraUser;
import org.georchestra.gateway.security.GeorchestraUserMapperExtension;
import org.slf4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import lombok.extern.slf4j.Slf4j;

/**
 * @author groldan
 *
 */
@Slf4j
public class OAuth2AuthenticationTokenUserMapper implements GeorchestraUserMapperExtension {

    @Override
    public Optional<GeorchestraUser> resolve(Authentication authToken) {
        return Optional.ofNullable(authToken)//
                .filter(OAuth2AuthenticationToken.class::isInstance)//
                .map(OAuth2AuthenticationToken.class::cast)//
                .filter(token -> !(token.getPrincipal() instanceof OidcUser))//
                .flatMap(this::map);
    }

    protected Optional<GeorchestraUser> map(OAuth2AuthenticationToken token) {
        logger().debug("Mapping {} authentication token from provider {}",
                token.getPrincipal().getClass().getSimpleName(), token.getAuthorizedClientRegistrationId());

        OAuth2User oAuth2User = token.getPrincipal();
        GeorchestraUser user = new GeorchestraUser();

        List<String> roles = resolveRoles(oAuth2User.getAuthorities());
        String userName = token.getName();

        Map<String, Object> attributes = oAuth2User.getAttributes();
        String login = (String) attributes.get("login");
        apply(user::setUsername, login, userName);
        apply(user::setEmail, (String) attributes.get("email"));
        user.setRoles(roles);

        return Optional.of(user);
    }

    protected List<String> resolveRoles(Collection<? extends GrantedAuthority> authorities) {
        List<String> roles = authorities.stream().map(GrantedAuthority::getAuthority).filter(scope -> {
            if (scope.startsWith("ROLE_SCOPE_") || scope.startsWith("SCOPE_")) {
                logger().debug("Excluding granted authority {}", scope);
                return false;
            }
            return true;
        }).toList();
        return roles;
    }

    protected void apply(Consumer<String> setter, String... candidates) {
        for (String candidateValue : candidates) {
            if (null != candidateValue) {
                setter.accept(candidateValue);
                break;
            }
        }
    }

    protected Logger logger() {
        return log;
    }
}
