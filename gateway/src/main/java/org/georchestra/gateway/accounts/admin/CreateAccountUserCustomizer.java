/*
 * Copyright (C) 2023 by the geOrchestra PSC
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
package org.georchestra.gateway.accounts.admin;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Collectors;

import org.georchestra.gateway.security.GeorchestraUserCustomizerExtension;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * {@link GeorchestraUserCustomizerExtension} that
 * {@link AccountManager#getOrCreate creates an account} when authenticated
 * through request headers (trusted proxy feature) or through OAuth2.
 */
@RequiredArgsConstructor
public class CreateAccountUserCustomizer implements GeorchestraUserCustomizerExtension, Ordered {

    private final @NonNull AccountManager accounts;

    /**
     * @return {@link Ordered#LOWEST_PRECEDENCE} so it runs after all other
     *         authentication customizations have been performed, such as setting
     *         additional roles from externalized configuration, etc.
     */
    public @Override int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }

    /**
     * @return the stored version (either existing or created as result of calling
     *         this method) of the user account, if the {@code Authentication}
     *         object is either an {@link OAuth2AuthenticationToken} or
     *         {@link PreAuthenticatedAuthenticationToken}; {@code mappedUser}
     *         otherwise.
     */
    @Override
    public @NonNull GeorchestraUser apply(@NonNull Authentication auth, @NonNull GeorchestraUser mappedUser) {
        final boolean isOauth2 = auth instanceof OAuth2AuthenticationToken;
        final boolean isPreAuth = auth instanceof PreAuthenticatedAuthenticationToken;
        if (isOauth2) {
            Objects.requireNonNull(mappedUser.getOAuth2ProviderId(), "GeorchestraUser.oAuth2ProviderId is null");
            GeorchestraUser user = accounts.getOrCreate(mappedUser);

            try {
//                ((OAuth2AuthenticationToken) auth).setDetails();
                Field field = AbstractAuthenticationToken.class.getDeclaredField("authorities");
                field.setAccessible(true);
                field.set(auth,
                        user.getRoles().stream().map(r -> new SimpleGrantedAuthority(r)).collect(Collectors.toList()));
            } catch (NoSuchFieldException e) {
            } catch (IllegalAccessException e) {
            }

        }
        if (isPreAuth) {
            Objects.requireNonNull(mappedUser.getUsername(), "GeorchestraUser.username is null");
        }
        if (isOauth2 || isPreAuth) {
            return accounts.getOrCreate(mappedUser);
        }
        return mappedUser;
    }

}
