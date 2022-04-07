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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.web.server.ServerWebExchange;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.With;

@Data
@NoArgsConstructor
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@With
public class GeorchestraOrganization implements Serializable {

    static final String GEORCHESTRA_ORGANIZATION_KEY = GeorchestraOrganization.class.getCanonicalName();

    private static final long serialVersionUID = -1;

    /** Provided by request header {@code sec-orgid}, usually stable UUID */
    private String id;

    /**
     * Provided by request header {@code sec-org}, legacy way of identifying by
     * LDAP's {@code org.cn} attribute, which may change over time
     */
    private String shortName;

    /**
     * Provided by request header {@code sec-orgname}, due to legacy LDAP mapping
     * {@code sec-orgname=org.o}
     */
    private String name;

    /** Provided by request header {@code sec-org-linkage} */
    private String linkage;

    /** Provided by request header {@code sec-org-address} */
    private String postalAddress;

    /** Provided by request header {@code sec-org-category} */
    private String category;

    /** Provided by request header {@code sec-org-description} */
    private String description;

    /** Provided by request header {@code sec-org-notes} */
    private String notes;

    /**
     * String that somehow represents the current version, may be a timestamp, a
     * hash, etc. Provided by request header {@code sec-lastupdated}
     */
    private String lastUpdated;

    /**
     * List of {@link GeorchestraUser#getUsername() user names} that belong to this
     * organization
     */
    private List<String> members = new ArrayList<>();

    public void setMembers(List<String> members) {
        this.members = members == null ? new ArrayList<>() : members;
    }

    public static Optional<GeorchestraOrganization> resolve(ServerWebExchange exchange) {
        return Optional.ofNullable(exchange.getAttribute(GEORCHESTRA_ORGANIZATION_KEY))
                .map(GeorchestraOrganization.class::cast);
    }

    public static void store(ServerWebExchange exchange, GeorchestraOrganization org) {
        exchange.getAttributes().put(GEORCHESTRA_ORGANIZATION_KEY, org);
    }
}