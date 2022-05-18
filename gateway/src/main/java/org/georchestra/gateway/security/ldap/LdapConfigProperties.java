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
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;
import lombok.Generated;

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
@Generated
@ConfigurationProperties(prefix = "georchestra.gateway.security")
public class LdapConfigProperties {

    private Map<String, Server> ldap = Map.of();

    public static @Data class Server {

        boolean enabled;

        private String url;

        /**
         * Base DN of the LDAP directory Base Distinguished Name of the LDAP directory.
         * Also named root or suffix, see
         * http://www.zytrax.com/books/ldap/apd/index.html#base
         * <p>
         * For example, georchestra's default baseDn is dc=georchestra,dc=org
         */
        private String baseDn;

        private Users users = new Users();
        private Roles roles = new Roles();
        private Organizations orgs = null;
    }

    public static @Data class Users {

        /**
         * Users RDN Relative distinguished name of the "users" LDAP organization unit.
         * E.g. if the complete name (or DN) is ou=users,dc=georchestra,dc=org, the RDN
         * is ou=users.
         */
        private String rdn = "ou=users";

        private String searchFilter = "(uid={0})";

        private String pendingUsersSearchBaseDN = "ou=pendingusers";

        private List<String> protectedUsers = List.of();
    }

    public static @Data class Roles {
        /**
         * Roles RDN Relative distinguished name of the "roles" LDAP organization unit.
         * E.g. if the complete name (or DN) is ou=roles,dc=georchestra,dc=org, the RDN
         * is ou=roles.
         */
        private String rdn = "ou=roles";

        private String searchFilter = "(member={0})";

        private List<String> protectedRoles = List.of();
    }

    public static @Data class Organizations {

        private String rdn = "ou=orgs";

        private String orgTypes = "Association,Company,NGO,Individual,Other";

        private String pendingOrgSearchBaseDN = "ou=pendingorgs";
    }
}
