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
import java.util.stream.Collectors;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.StringUtils;
import org.springframework.validation.annotation.Validated;

import lombok.Data;
import lombok.Generated;
import lombok.Getter;

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
@Validated
public class LdapConfigProperties {

    private Map<String, Server> ldap = Map.of();

    public static class LdapServerConfig extends Server {

        private @Getter String name;

        public LdapServerConfig(String name, Server value) {
            this.name = name;
            super.setUrl(value.getUrl());
            super.setBaseDn(value.getBaseDn());
            super.setEnabled(value.isEnabled());
            super.setExtended(value.isExtended());
            super.setUsers(value.getUsers());
            super.setRoles(value.getRoles());
            super.setOrgs(value.getOrgs());
        }

    }

    public List<LdapServerConfig> configs() {
        return ldap.entrySet().stream().map(e -> new LdapServerConfig(e.getKey(), e.getValue()))
                .collect(Collectors.toList());
    }

    public static @Data class Server {

        boolean enabled;

        boolean extended;

        @NotBlank
        private String url;

        /**
         * Base DN of the LDAP directory Base Distinguished Name of the LDAP directory.
         * Also named root or suffix, see
         * http://www.zytrax.com/books/ldap/apd/index.html#base
         * <p>
         * For example, georchestra's default baseDn is dc=georchestra,dc=org
         */
        @NotBlank
        private String baseDn;

        @NotNull
        private Users users = new Users();

        @NotNull
        private Roles roles = new Roles();

        private Organizations orgs = null;

        /**
         * Configured the LDAP authentication source to use georchestra specific
         * extensions. For example, when using the default OpenLDAP database with
         * additional information like pending users and organizations
         */
        public boolean hasGeorchestraExtensions() {
            if (this.isExtended()) {// forced use of extensions
                return true;
            }
            // heuristically determining whether it's a georchestra extended db
            Users users = getUsers();
            if (StringUtils.hasText(users.getPendingUsersSearchBaseDN())) {
                return true;
            }
            Roles roles = getRoles();
            if (roles.getProtectedRoles() != null && !roles.getProtectedRoles().isEmpty()) {
                return true;
            }
            if (null != getOrgs()) {
                return true;
            }
            return false;
        }
    }

    public static @Data class Users {

        /**
         * Users RDN Relative distinguished name of the "users" LDAP organization unit.
         * E.g. if the complete name (or DN) is ou=users,dc=georchestra,dc=org, the RDN
         * is ou=users.
         */
        @NotBlank
        private String rdn = "ou=users";

        @NotBlank
        private String searchFilter = "(uid={0})";

        /**
         * E.g. ou=pendingusers
         */
        private String pendingUsersSearchBaseDN;

        private List<String> protectedUsers = List.of();
    }

    public static @Data class Roles {
        /**
         * Roles RDN Relative distinguished name of the "roles" LDAP organization unit.
         * E.g. if the complete name (or DN) is ou=roles,dc=georchestra,dc=org, the RDN
         * is ou=roles.
         */
        @NotBlank
        private String rdn = "ou=roles";

        @NotBlank
        private String searchFilter = "(member={0})";

        @NotBlank
        private String prefix = "ROLE_";

        private boolean upperCase = true;

        private List<String> protectedRoles = List.of();
    }

    public static @Data class Organizations {

        @NotBlank
        private String rdn = "ou=orgs";

        @NotBlank
        private String orgTypes = "Association,Company,NGO,Individual,Other";

        @NotBlank
        private String pendingOrgSearchBaseDN = "ou=pendingorgs";
    }
}
