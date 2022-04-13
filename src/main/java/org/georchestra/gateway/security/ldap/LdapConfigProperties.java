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
package org.georchestra.gateway.security.ldap;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

/**
 * Config properties, usually loaded from georchestra datadir's
 * {@literal default.properties}.
 * <p>
 * e.g.:
 * 
 * <pre>
 *{@code 
 * ldapHost=localhost
 * ldapPort=389
 * ldapScheme=ldap
 * ldapBaseDn=dc=georchestra,dc=org
 * ldapUsersRdn=ou=users
 * ldapRolesRdn=ou=roles
 * ldapOrgsRdn=ou=orgs
 * }
 * </pre>
 */
@Data
@ConfigurationProperties(prefix = "georchestra.gateway.security.ldap")
public class LdapConfigProperties {

    private String url;

    /**
     * Base DN of the LDAP directory Base Distinguished Name of the LDAP directory.
     * Also named root or suffix, see
     * http://www.zytrax.com/books/ldap/apd/index.html#base
     */

    private String baseDn = "dc=georchestra,dc=org";

    /**
     * Users RDN Relative distinguished name of the "users" LDAP organization unit.
     * E.g. if the complete name (or DN) is ou=users,dc=georchestra,dc=org, the RDN
     * is ou=users.
     */
    private String usersRdn = "ou=users";

    private String userSearchFilter = "(uid={0})";

    /**
     * Roles RDN Relative distinguished name of the "roles" LDAP organization unit.
     * E.g. if the complete name (or DN) is ou=roles,dc=georchestra,dc=org, the RDN
     * is ou=roles.
     */
    private String rolesRdn = "ou=roles";

    private String rolesSearchFilter = "(member={0})";

    private String orgsRdn = "ou=orgs";

    private String pendingOrgSearchBaseDN = "ou=pendingorgs";

    private String orgTypeValues = "Association,Company,NGO,Individual,Other";

    private List<String> protectedRolesList = List.of("ADMINISTRATOR", "EXTRACTORAPP", "GN_.*", "ORGADMIN", "REFERENT",
            "USER", "SUPERUSER");

    private List<String> protectedUsersList = List.of("geoserver_privileged_user");
}
