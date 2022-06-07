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

package org.georchestra.gateway.security.ldap.activedirectory;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.georchestra.gateway.security.ldap.basic.LdapAuthenticatedUserMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.annotation.UserConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.ReactiveAuthenticationManagerAdapter;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;

/**
 * Tests {@link ApplicationContext} contributions of
 * {@link ActiveDirectoryAuthenticationConfiguration}
 */
class ActiveDirectoryAuthenticationConfigurationTest {

    private ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(UserConfigurations.of(ActiveDirectoryAuthenticationConfiguration.class));

    @SuppressWarnings("unchecked")
    public @Test void contextContributions_empty_config() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).getBean("enabledActiveDirectoryLdapConfigs").isInstanceOf(List.class);
            assertThat(context.getBean("enabledActiveDirectoryLdapConfigs", List.class)).isEmpty();
            assertThat(context.getBean("activeDirectoryLdapAuthenticationProviders", List.class)).isEmpty();

            assertThat(context.getBean("activeDirectoryAuthenticatedUserMapper").getClass().getName())
                    .isEqualTo("org.springframework.beans.factory.support.NullBean");

            assertThat(context.getBean("activeDirectoryAuthenticationManager").getClass().getName())
                    .isEqualTo("org.springframework.beans.factory.support.NullBean");
        });
    }

    @SuppressWarnings("unchecked")
    public @Test void contextContributions_single_config() {
        runner.withPropertyValues(""//
                , "georchestra.gateway.security.ldap.ad.enabled: true" //
                , "georchestra.gateway.security.ldap.ad.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad.url: ldap://test.ldap2:839" //
                , "georchestra.gateway.security.ldap.ad.domain: my.domain.com" //
                , "georchestra.gateway.security.ldap.ad.baseDn: dc=my,dc=domain,dc=com" //
                ,
                "georchestra.gateway.security.ldap.ad.users.searchFilter: (&(objectClass=user)(userPrincipalName={0}))" //
        ).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).getBean("enabledActiveDirectoryLdapConfigs").isInstanceOf(List.class);
            assertThat(context.getBean("enabledActiveDirectoryLdapConfigs", List.class)).hasSize(1);
            assertThat(context.getBean("activeDirectoryLdapAuthenticationProviders", List.class)).hasSize(1);
            assertThat(context.getBean("activeDirectoryLdapAuthenticationProviders", List.class)).singleElement()
                    .isInstanceOf(ActiveDirectoryLdapAuthenticationProvider.class);

            assertThat(context.getBean("activeDirectoryAuthenticatedUserMapper"))
                    .isInstanceOf(LdapAuthenticatedUserMapper.class);

            assertThat(context.getBean("activeDirectoryAuthenticationManager"))
                    .isInstanceOf(ReactiveAuthenticationManagerAdapter.class);
        });
    }

    @SuppressWarnings("unchecked")
    public @Test void contextContributions_multiple_configs() {
        runner.withPropertyValues(""//
                , "georchestra.gateway.security.ldap.ad1.enabled: true" //
                , "georchestra.gateway.security.ldap.ad1.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad1.url: ldap://test.ldap2:839" //
                , "georchestra.gateway.security.ldap.ad1.domain: my.domain.com" //
                , "georchestra.gateway.security.ldap.ad1.baseDn: dc=my,dc=domain,dc=com" //
                ,
                "georchestra.gateway.security.ldap.ad.users.searchFilter: (&(objectClass=user)(userPrincipalName={0}))" //
                //
                , "georchestra.gateway.security.ldap.ad2.enabled: true" //
                , "georchestra.gateway.security.ldap.ad2.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad2.url: ldap://test.ldap2:839" //
        ).run(context -> {

            assertThat(context).hasNotFailed();
            assertThat(context.getBean("enabledActiveDirectoryLdapConfigs", List.class)).hasSize(2);
            assertThat(context.getBean("activeDirectoryLdapAuthenticationProviders", List.class)).hasSize(2);
            assertThat(context.getBean("activeDirectoryLdapAuthenticationProviders", List.class)).hasSize(2)
                    .allMatch(ActiveDirectoryLdapAuthenticationProvider.class::isInstance);

            assertThat(context.getBean("activeDirectoryAuthenticatedUserMapper"))
                    .isInstanceOf(LdapAuthenticatedUserMapper.class);

            assertThat(context.getBean("activeDirectoryAuthenticationManager"))
                    .isInstanceOf(ReactiveAuthenticationManagerAdapter.class);
        });
    }
}
