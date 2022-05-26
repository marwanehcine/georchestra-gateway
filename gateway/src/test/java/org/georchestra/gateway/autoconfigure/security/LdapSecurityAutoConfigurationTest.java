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

package org.georchestra.gateway.autoconfigure.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.georchestra.gateway.security.ldap.DemultiplexingUsersApi;
import org.georchestra.gateway.security.ldap.GeorchestraLdapAuthenticatedUserMapper;
import org.georchestra.gateway.security.ldap.LdapAuthenticatedUserMapper;
import org.georchestra.gateway.security.ldap.LdapConfigProperties;
import org.georchestra.gateway.security.ldap.MultipleLdapSecurityConfiguration;
import org.georchestra.gateway.security.ldap.MultipleLdapSecurityConfiguration.LDAPAuthenticationCustomizer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;

/**
 * Assert context contributions of {@link LdapSecurityAutoConfiguration} /
 * {@link MultipleLdapSecurityConfiguration}
 *
 */
class LdapSecurityAutoConfigurationTest {
    private ApplicationContextRunner runner = new ApplicationContextRunner().withConfiguration(AutoConfigurations
            .of(LdapSecurityAutoConfiguration.class, GeorchestraLdapAccountManagementAutoConfiguration.class));

    @Test
    void testDisabledByDefault() {
        testDisabled(runner);
    }

    @Test
    void testDisabledExplicitly() {
        testDisabled(runner.withPropertyValues("georchestra.gateway.security.ldap.default.enabled=false"));
    }

    private void testDisabled(ApplicationContextRunner runner) {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(LdapConfigProperties.class);
            assertThat(context).doesNotHaveBean(LDAPAuthenticationCustomizer.class);
            assertThat(context).doesNotHaveBean(LdapAuthenticatedUserMapper.class);
            assertThat(context).doesNotHaveBean(BaseLdapPathContextSource.class);
            assertThat(context).doesNotHaveBean(DefaultLdapAuthoritiesPopulator.class);
            assertThat(context).doesNotHaveBean("ldapAuthenticationWebFilter");
            assertThat(context).doesNotHaveBean("ldapAuthenticationManager");
            assertThat(context).doesNotHaveBean("ldapAuthoritiesMapper");
        });
    }

    @Test
    void testDefaultLDAPEnabled() {
        runner.withPropertyValues(//
                "georchestra.gateway.security.ldap.default.enabled: true" //
                , "georchestra.gateway.security.ldap.default.extended: false"//
                , "georchestra.gateway.security.ldap.default.url: ldap://localhost:3891"//
                , "georchestra.gateway.security.ldap.default.baseDn: dc=georchestra,dc=org"//
                , "georchestra.gateway.security.ldap.default.users.rdn: ou=users"//
                , "georchestra.gateway.security.ldap.default.users.searchFilter: (uid={0})"//
                , "georchestra.gateway.security.ldap.default.users.pendingUsersSearchBaseDN: ou=pendingusers"//
                , "georchestra.gateway.security.ldap.default.users.protectedUsers: geoserver_privileged_user"//
                , "georchestra.gateway.security.ldap.default.roles.rdn: ou=roles"//
                , "georchestra.gateway.security.ldap.default.roles.searchFilter: (member={0})"//
                , "georchestra.gateway.security.ldap.default.roles.protectedRoles: ADMINISTRATOR, EXTRACTORAPP"//
                , "georchestra.gateway.security.ldap.default.orgs.rdn: ou=orgs"//
                , "georchestra.gateway.security.ldap.default.orgs.orgTypes: Association,Company"//
                , "georchestra.gateway.security.ldap.default.orgs.pendingOrgSearchBaseDN: ou=pendingorgs"//
        )//
                .run(context -> {
                    assertThat(context).hasSingleBean(LdapAuthenticatedUserMapper.class);
                    assertThat(context).hasSingleBean(GeorchestraLdapAuthenticatedUserMapper.class);
                    assertThat(context).hasSingleBean(DemultiplexingUsersApi.class);
                    assertThat(context).hasBean("ldapHttpBasicLoginFormEnablerExtension");
                    assertThat(context).hasBean("ldapAuthenticatedUserMapper");
                    assertThat(context).hasBean("ldapAuthenticationManager");
                    DemultiplexingUsersApi usersApi = context.getBean(DemultiplexingUsersApi.class);
                    assertThat(usersApi.getTargetNames()).containsExactlyInAnyOrder("default");
                });
    }

    @Test
    void testMultipleLDAPEnabled() {
        runner.withPropertyValues(//
                "georchestra.gateway.security.ldap.default.enabled: true" //
                , "georchestra.gateway.security.ldap.default.extended: true"//
                , "georchestra.gateway.security.ldap.default.url: ldap://localhost:3891"//
                , "georchestra.gateway.security.ldap.default.baseDn: dc=georchestra,dc=org"//
                , "georchestra.gateway.security.ldap.default.users.rdn: ou=users"//
                , "georchestra.gateway.security.ldap.default.users.searchFilter: (uid={0})"//
                , "georchestra.gateway.security.ldap.default.users.pendingUsersSearchBaseDN: ou=pendingusers"//
                , "georchestra.gateway.security.ldap.default.users.protectedUsers: geoserver_privileged_user"//
                , "georchestra.gateway.security.ldap.default.roles.rdn: ou=roles"//
                , "georchestra.gateway.security.ldap.default.roles.searchFilter: (member={0})"//
                , "georchestra.gateway.security.ldap.default.roles.protectedRoles: ADMINISTRATOR, EXTRACTORAPP"//
                , "georchestra.gateway.security.ldap.default.orgs.rdn: ou=orgs"//
                , "georchestra.gateway.security.ldap.default.orgs.orgTypes: Association,Company"//
                , "georchestra.gateway.security.ldap.default.orgs.pendingOrgSearchBaseDN: ou=pendingorgs"//
                ///
                , "georchestra.gateway.security.ldap.second.enabled: true" //
                , "georchestra.gateway.security.ldap.second.extended: true" //
                , "georchestra.gateway.security.ldap.second.url: ldap://localhost:3892"//
                , "georchestra.gateway.security.ldap.second.baseDn: dc=externals,dc=org"//
                , "georchestra.gateway.security.ldap.second.users.rdn: ou=users"//
                , "georchestra.gateway.security.ldap.second.users.searchFilter: (uid={0})"//
                , "georchestra.gateway.security.ldap.second.roles.rdn: ou=roles"//
                , "georchestra.gateway.security.ldap.second.roles.searchFilter: (member={0})"//
        )//
                .run(context -> {
                    assertThat(context).hasSingleBean(LdapAuthenticatedUserMapper.class);
                    assertThat(context).hasSingleBean(GeorchestraLdapAuthenticatedUserMapper.class);
                    assertThat(context).hasSingleBean(DemultiplexingUsersApi.class);
                    assertThat(context).hasBean("ldapHttpBasicLoginFormEnablerExtension");
                    assertThat(context).hasBean("ldapAuthenticatedUserMapper");
                    assertThat(context).hasBean("ldapAuthenticationManager");
                    DemultiplexingUsersApi usersApi = context.getBean(DemultiplexingUsersApi.class);
                    assertThat(usersApi.getTargetNames()).containsExactlyInAnyOrder("default", "second");
                });
        ;
    }
}
