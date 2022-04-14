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
package org.georchestra.gateway.model;

import java.util.List;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import lombok.Data;
import lombok.experimental.Accessors;

/**
 * Models access rules to intercepted Ant-pattern URIs based on roles.
 * <p>
 * Role names are defined by the authenticated user's
 * {@link AbstractAuthenticationToken#getAuthorities() authority names} (i.e.
 * {@link GrantedAuthority#getAuthority()}) .
 */
@Data
@Accessors(chain = true)
public class RoleBasedAccessRule {

    /**
     * List of Ant pattern URI's, excluding the application context, the Gateway
     * shall intercept and apply the access rules defined here. E.g.
     */
    private List<String> interceptUrl = List.of();

    /**
     * Whether anonymous (unauthenticated) access is to be granted to the
     * intercepted URIs. If {@code true}, no further specification is applied to the
     * intercepted urls (i.e. if set, {@link #allowedRoles} are ignored).
     */
    private boolean anonymous = false;

    /**
     * Requires an authenticated user, regardless of the roles. If there are
     * {@link #allowedRoles} defined, this property is assumed to be {@code true},
     * despite whether it's set or not.
     */
    private boolean authenticated = false;

    /**
     * Role names that the authenticated user must be part of to be granted access
     * to the intercepted URIs. The ROLE_ prefix is optional. For example, the role
     * set [ROLE_USER, ROLE_AUDITOR] is equivalent to [USER, AUDITOR]
     */
    private List<String> allowedRoles = List.of();
}
