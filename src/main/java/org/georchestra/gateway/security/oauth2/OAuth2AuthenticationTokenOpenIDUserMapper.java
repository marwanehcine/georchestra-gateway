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

import java.util.Map;
import java.util.Optional;
import java.util.function.Consumer;

import org.georchestra.gateway.model.GeorchestraUser;
import org.slf4j.Logger;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.AddressStandardClaim;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimAccessor;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import lombok.extern.slf4j.Slf4j;

/**
 * @author groldan
 *
 */
@Slf4j
public class OAuth2AuthenticationTokenOpenIDUserMapper extends OAuth2AuthenticationTokenUserMapper {

    @Override
    public Optional<GeorchestraUser> resolve(Authentication authToken) {
        return Optional.ofNullable(authToken)//
                .filter(OAuth2AuthenticationToken.class::isInstance)//
                .map(OAuth2AuthenticationToken.class::cast)//
                .filter(token -> token.getPrincipal() instanceof OidcUser)//
                .flatMap(this::map);
    }

    protected @Override Optional<GeorchestraUser> map(OAuth2AuthenticationToken token) {
        GeorchestraUser user = super.map(token).orElseGet(GeorchestraUser::new);

        OidcUser oidcUser = (OidcUser) token.getPrincipal();

        apply((StandardClaimAccessor) oidcUser, user);

        // OAuth2 non-standardized attributes
        Map<String, Object> attributes = oidcUser.getAttributes();
        // OpenId Connect merged claims from OidcUserInfo and OidcIdToken
        Map<String, Object> claims = oidcUser.getClaims();
        OidcUserInfo userInfo = oidcUser.getUserInfo();
        OidcIdToken idToken = oidcUser.getIdToken();

        return Optional.of(user);
    }

    private void apply(StandardClaimAccessor standardClaims, GeorchestraUser target) {
        AddressStandardClaim address = standardClaims.getAddress();
        String preferredUsername = standardClaims.getPreferredUsername();
        String givenName = standardClaims.getGivenName();
        String familyName = standardClaims.getFamilyName();

        String fullName = standardClaims.getFullName();
        String email = standardClaims.getEmail();
        String phoneNumber = standardClaims.getPhoneNumber();

        apply(target::setUsername, preferredUsername, email);
        apply(target::setFirstName, givenName);
        apply(target::setLastName, familyName);
        apply(target::setEmail, email);
        apply(target::setTelephoneNumber, phoneNumber);
    }

    protected void apply(Consumer<String> setter, String... candidates) {
        for (String candidateValue : candidates) {
            if (null != candidateValue) {
                setter.accept(candidateValue);
                break;
            }
        }
    }

    protected @Override Logger logger() {
        return log;
    }
}
