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

import org.georchestra.gateway.security.ldap.LdapAuthenticatedUserMapper;
import org.georchestra.gateway.security.ldap.LdapConfigProperties;
import org.georchestra.gateway.security.ldap.LdapSecurityConfiguration.LDAPAuthenticationCustomizer;
import org.georchestra.security.api.OrganizationsApi;
import org.georchestra.security.api.RolesApi;
import org.georchestra.security.api.UsersApi;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;

/**
 * Assert context contributions of {@link LdapSecurityAutoConfiguration}
 *
 */
class LdapSecurityAutoConfigurationTest {
    private ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(LdapSecurityAutoConfiguration.class));

    @Test
    void testDisabledByDefault() {
        testDisabled(runner);
    }

    @Test
    void testDisabledExplicitly() {
        testDisabled(runner.withPropertyValues("georchestra.gateway.security.ldap.enabled=false"));
    }

    @Test
    void testEnabled() {
        runner.withPropertyValues(//
                "georchestra.gateway.security.ldap.enabled=true", //
                "georchestra.gateway.security.ldap.url=ldap://localhost:3891"//
        )//
                .run(context -> {
                    assertThat(context).hasSingleBean(UsersApi.class);
                    assertThat(context).hasSingleBean(OrganizationsApi.class);
                    assertThat(context).hasSingleBean(RolesApi.class);
                    assertThat(context).hasSingleBean(LdapConfigProperties.class);
                    assertThat(context).hasSingleBean(LDAPAuthenticationCustomizer.class);
                    assertThat(context).hasSingleBean(LdapAuthenticatedUserMapper.class);
                    assertThat(context).hasSingleBean(BaseLdapPathContextSource.class);
                    assertThat(context).hasSingleBean(DefaultLdapAuthoritiesPopulator.class);
                    assertThat(context).hasBean("ldapAuthenticationWebFilter");
                    assertThat(context).hasBean("ldapAuthenticationManager");
                    assertThat(context).hasBean("ldapAuthoritiesMapper");
                });
        ;
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
}
