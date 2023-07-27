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

package org.georchestra.gateway.security.ldap.extended;

import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import org.georchestra.security.api.UsersApi;
import org.georchestra.security.model.GeorchestraUser;

import com.google.common.annotations.VisibleForTesting;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Demultiplexer to call the appropriate {@link UsersApi} based on the
 * authentication's service name, as provided by
 * {@link GeorchestraUserNamePasswordAuthenticationToken#getConfigName()},
 * matching a configured LDAP database through the configuration properties
 * {@code georchestra.gateway.security.<serviceName>.*}.
 * <p>
 * Ensures {@link GeorchestraLdapAuthenticatedUserMapper} queries the same LDAP
 * database the authentication object was created from, avoiding the need to
 * disambiguate if two configured LDAP databases have accounts with the same
 * {@literal username}.
 */
@RequiredArgsConstructor
class DemultiplexingUsersApi {

    private final @NonNull Map<String, UsersApi> targets;

    public @VisibleForTesting Set<String> getTargetNames() {
        return new HashSet<>(targets.keySet());
    }

    /**
     * 
     * @param serviceName the configured LDAP service name, as from the
     *                    configuration properties
     *                    {@code georchestra.gateway.security.<serviceName>}
     * @param username    the user name to query the service's {@link UsersApi} with
     * 
     * @return the {@link GeorchestraUser} returned by the service's
     *         {@link UsersApi}, or {@link Optional#empty() empty} if not found
     */
    public Optional<GeorchestraUser> findByUsername(@NonNull String serviceName, @NonNull String username) {
        UsersApi target = targets.get(serviceName);
        Objects.requireNonNull(target, () -> "No UsersApi found for config named " + serviceName);
        return target.findByUsername(username);
    }

    public Optional<GeorchestraUser> findByEmail(@NonNull String serviceName, @NonNull String email) {
        UsersApi target = targets.get(serviceName);
        Objects.requireNonNull(target, () -> "No UsersApi found for config named " + serviceName);
        return target.findByEmail(email);
    }
}
