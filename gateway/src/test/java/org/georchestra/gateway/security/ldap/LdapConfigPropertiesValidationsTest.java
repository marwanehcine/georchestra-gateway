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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Optional;

import org.georchestra.gateway.security.ldap.activedirectory.ActiveDirectoryLdapServerConfig;
import org.georchestra.gateway.security.ldap.basic.LdapServerConfig;
import org.georchestra.gateway.security.ldap.extended.ExtendedLdapConfig;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

/**
 * Test cases for {@link LdapConfigPropertiesValidations}.
 * <p>
 * {@link LdapConfigPropertiesValidations} will forbid application startup if
 * {@link LdapConfigProperties} is invalid.
 * <p>
 * {@link LdapConfigProperties} is loaded from application properties, usually
 * from georchestra datadirectory's {@literal gateway/gateway.yaml}
 */
class LdapConfigPropertiesValidationsTest {

    @EnableConfigurationProperties(LdapConfigProperties.class)
    static @Configuration class EnableConfigProps {

    }

    private ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(EnableConfigProps.class);

    public @Test void no_ldap_configs() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(LdapConfigProperties.class);
            assertThat(context.getBean(LdapConfigProperties.class).getLdap()).isEmpty();
        });
    }

    public @Test void no_ldap_enabled() {
        runner.withPropertyValues(//
                "georchestra.gateway.security.ldap.ldap1.enabled: false" //
                , "georchestra.gateway.security.ldap.ldap2.enabled: false" //
        ).run(context -> {
            assertThat(context).hasSingleBean(LdapConfigProperties.class);
            LdapConfigProperties config = context.getBean(LdapConfigProperties.class);
            assertThat(config.getLdap()).hasSize(2);
            assertThat(config.simpleEnabled()).isEmpty();
            assertThat(config.extendedEnabled()).isEmpty();
            assertThat(config.activeDirectoryEnabled()).isEmpty();
        });
    }

    public @Test void validates_extended_and_activedirectory_are_mutually_exclusive() {
        runner.withPropertyValues(""//
                , "georchestra.gateway.security.ldap.ldap1.enabled: true" //
                , "georchestra.gateway.security.ldap.ldap1.extended: true" //
                , "georchestra.gateway.security.ldap.ldap1.activeDirectory: true" //
        ).run(context -> {
            assertThat(context).getFailure()//
                    .hasStackTraceContaining("extended and activeDirectory are mutually exclusive")
                    .hasStackTraceContaining("ldap.[ldap1].extended")//
                    .hasStackTraceContaining("ldap.[ldap1].activeDirectory");
        });
    }

    public @Test void validates_common_url_is_mandatory_if_enabled() {
        runner.withPropertyValues(""//
                , "georchestra.gateway.security.ldap.basic1.enabled: true" //
                , "georchestra.gateway.security.ldap.basic1.url:" //
                , "georchestra.gateway.security.ldap.extended1.enabled: true" //
                , "georchestra.gateway.security.ldap.extended1.extended: true" //
                , "georchestra.gateway.security.ldap.extended1.url: " //
                , "georchestra.gateway.security.ldap.ad1.enabled: true" //
                , "georchestra.gateway.security.ldap.ad1.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad1.url:" //
                , "georchestra.gateway.security.ldap.basic2.enabled: false" //
                , "georchestra.gateway.security.ldap.basic2.url:" //
        ).run(context -> {
            assertThat(context).getFailure().hasStackTraceContaining("LDAP url is required")
                    .hasStackTraceContaining("ldap.[basic1].url").hasStackTraceContaining("ldap.[extended1].url")
                    .hasStackTraceContaining("ldap.[ad1].url");
        });
    }

    public @Test void validates_common_url_not_set_does_not_fail_if_not_enabled() {
        runner.withPropertyValues(""//
                , "georchestra.gateway.security.ldap.basic1.enabled: false" //
                , "georchestra.gateway.security.ldap.basic1.url:" //
        ).run(context -> {
            assertThat(context).hasNotFailed();
        });
    }

    public @Test void validates_activeDirectory_baseDn_is_optional() {
        runner.withPropertyValues(""//
        // first AD config
                , "georchestra.gateway.security.ldap.ad1.enabled: true" //
                , "georchestra.gateway.security.ldap.ad1.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad1.url: ldap://test.ldap:839" //
                , "georchestra.gateway.security.ldap.ad1.baseDn: " //
                // second AD config
                , "georchestra.gateway.security.ldap.ad2.enabled: true" //
                , "georchestra.gateway.security.ldap.ad2.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad2.url: ldap://test.ldap2:839" //
                , "georchestra.gateway.security.ldap.ad2.baseDn: dc=my,dc=company,dc=com" //
        ).run(context -> {
            LdapConfigProperties config = context.getBean(LdapConfigProperties.class);
            List<ActiveDirectoryLdapServerConfig> adConfigs = config.activeDirectoryEnabled();
            assertThat(adConfigs).hasSize(2);
            assertThat(adConfigs.get(0)).hasFieldOrPropertyWithValue("rootDn", Optional.empty());
            assertThat(adConfigs.get(1)).hasFieldOrPropertyWithValue("rootDn", Optional.of("dc=my,dc=company,dc=com"));
        });
    }

    public @Test void validates_activeDirectory_domain_is_optional() {
        runner.withPropertyValues(""//
        // first AD config
                , "georchestra.gateway.security.ldap.ad1.enabled: true" //
                , "georchestra.gateway.security.ldap.ad1.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad1.url: ldap://test.ldap:839" //
                , "georchestra.gateway.security.ldap.ad1.domain: " //
                // second AD config
                , "georchestra.gateway.security.ldap.ad2.enabled: true" //
                , "georchestra.gateway.security.ldap.ad2.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad2.url: ldap://test.ldap2:839" //
                , "georchestra.gateway.security.ldap.ad2.domain: my.company.com" //
        ).run(context -> {
            LdapConfigProperties config = context.getBean(LdapConfigProperties.class);
            List<ActiveDirectoryLdapServerConfig> adConfigs = config.activeDirectoryEnabled();
            assertThat(adConfigs).hasSize(2);
            assertThat(adConfigs.get(0)).hasFieldOrPropertyWithValue("domain", Optional.empty());
            assertThat(adConfigs.get(1)).hasFieldOrPropertyWithValue("domain", Optional.of("my.company.com"));
        });
    }

    public @Test void validates_activeDirectory_searchFilter_is_optional() {
        runner.withPropertyValues(""//
        // first AD config
                , "georchestra.gateway.security.ldap.ad1.enabled: true" //
                , "georchestra.gateway.security.ldap.ad1.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad1.url: ldap://test.ldap:839" //
                , "georchestra.gateway.security.ldap.ad1.users.searchFilter: "//
                // second AD config
                , "georchestra.gateway.security.ldap.ad2.enabled: true" //
                , "georchestra.gateway.security.ldap.ad2.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad2.url: ldap://test.ldap2:839" //
                ,
                "georchestra.gateway.security.ldap.ad2.users.searchFilter: (&(objectClass=user)(userPrincipalName={0}))" //
        ).run(context -> {
            LdapConfigProperties config = context.getBean(LdapConfigProperties.class);
            List<ActiveDirectoryLdapServerConfig> adConfigs = config.activeDirectoryEnabled();
            assertThat(adConfigs).hasSize(2);
            assertThat(adConfigs.get(0)).hasFieldOrPropertyWithValue("searchFilter", Optional.empty());
            assertThat(adConfigs.get(1)).hasFieldOrPropertyWithValue("searchFilter",
                    Optional.of("(&(objectClass=user)(userPrincipalName={0}))"));
        });
    }

    public @Test void validates_basic_and_extended_baseDn_is_mandatory() {
        runner.withPropertyValues(""//
        // Basic LDAP config
                , "georchestra.gateway.security.ldap.ldap1.enabled: true" //
                , "georchestra.gateway.security.ldap.ldap1.url: ldap://ldap1.test.com:839" //
                , "georchestra.gateway.security.ldap.ldap1.baseDn: " //
                // Georchestra extended LDAP config
                , "georchestra.gateway.security.ldap.extended1.enabled: true" //
                , "georchestra.gateway.security.ldap.extended1.extended: true" //
                , "georchestra.gateway.security.ldap.extended1.url: ldap://ldap2.test.com:839" //
                , "georchestra.gateway.security.ldap.extended1.baseDn: " //
        ).run(context -> {
            assertThat(context).getFailure()//
                    .hasStackTraceContaining("LDAP base DN is required")//
                    .hasStackTraceContaining("ldap.[ldap1].baseDn").hasStackTraceContaining("ldap.[extended1].baseDn");
        });
    }

    public @Test void validates_basic_and_extended_users_rdn_is_mandatory() {
        runner.withPropertyValues(""//
        // Basic LDAP config
                , "georchestra.gateway.security.ldap.ldap1.enabled: true" //
                , "georchestra.gateway.security.ldap.ldap1.url: ldap://ldap1.test.com:839" //
                , "georchestra.gateway.security.ldap.ldap1.baseDn: dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.rdn: " //
                // Georchestra extended LDAP config
                , "georchestra.gateway.security.ldap.extended1.enabled: true" //
                , "georchestra.gateway.security.ldap.extended1.extended: true" //
                , "georchestra.gateway.security.ldap.extended1.url: ldap://ldap2.test.com:839" //
                , "georchestra.gateway.security.ldap.extended1.baseDn: dc=test,dc=com" //
                , "georchestra.gateway.security.ldap.extended1.users.rdn: " //
        ).run(context -> {
            assertThat(context).getFailure()//
                    .hasStackTraceContaining("LDAP users RDN (Relative Distinguished Name) is required")//
                    .hasStackTraceContaining("ldap.[ldap1].users.rdn")//
                    .hasStackTraceContaining("ldap.[extended1].users.rdn");
        });
    }

    public @Test void validates_basic_and_extended_users_searchFilter_is_mandatory() {
        runner.withPropertyValues(""//
        // Basic LDAP config
                , "georchestra.gateway.security.ldap.ldap1.enabled: true" //
                , "georchestra.gateway.security.ldap.ldap1.url: ldap://ldap1.test.com:839" //
                , "georchestra.gateway.security.ldap.ldap1.baseDn: dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.rdn: ou=users,dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.searchFilter: " //
                // Georchestra extended LDAP config
                , "georchestra.gateway.security.ldap.extended1.enabled: true" //
                , "georchestra.gateway.security.ldap.extended1.extended: true" //
                , "georchestra.gateway.security.ldap.extended1.url: ldap://ldap2.test.com:839" //
                , "georchestra.gateway.security.ldap.extended1.baseDn: dc=test,dc=com" //
                , "georchestra.gateway.security.ldap.extended1.users.rdn: ou=users,dc=tes,dc=com" //
                , "georchestra.gateway.security.ldap.extended1.users.searchFilter: " //
        ).run(context -> {
            assertThat(context).getFailure()//
                    .hasStackTraceContaining("LDAP users searchFilter is required for regular LDAP configs")//
                    .hasStackTraceContaining("ldap.[ldap1].users.searchFilter")//
                    .hasStackTraceContaining("ldap.[extended1].users.searchFilter");
        });
    }

    public @Test void validates_basic_and_extended_roles_rdn_is_mandatory() {
        runner.withPropertyValues(""//
        // Basic LDAP config
                , "georchestra.gateway.security.ldap.ldap1.enabled: true" //
                , "georchestra.gateway.security.ldap.ldap1.url: ldap://ldap1.test.com:839" //
                , "georchestra.gateway.security.ldap.ldap1.baseDn: dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.rdn: ou=users,dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.searchFilter: (uid={0})" //
                , "georchestra.gateway.security.ldap.ldap1.roles.rdn: " //
                // Georchestra extended LDAP config
                , "georchestra.gateway.security.ldap.extended1.enabled: true" //
                , "georchestra.gateway.security.ldap.extended1.extended: true" //
                , "georchestra.gateway.security.ldap.extended1.url: ldap://ldap2.test.com:839" //
                , "georchestra.gateway.security.ldap.extended1.baseDn: dc=test,dc=com" //
                , "georchestra.gateway.security.ldap.extended1.users.rdn: ou=users,dc=tes,dc=com" //
                , "georchestra.gateway.security.ldap.extended1.users.searchFilter: (uid={0})" //
                , "georchestra.gateway.security.ldap.extended1.roles.rdn: " //
        ).run(context -> {
            assertThat(context).getFailure()//
                    .hasStackTraceContaining("Roles Relative distinguished name is required")//
                    .hasStackTraceContaining("ldap.[ldap1].roles.rdn")//
                    .hasStackTraceContaining("ldap.[extended1].roles.rdn");
        });
    }

    public @Test void validates_basic_and_extended_roles_searchFilter_is_mandatory() {
        runner.withPropertyValues(""//
        // Basic LDAP config
                , "georchestra.gateway.security.ldap.ldap1.enabled: true" //
                , "georchestra.gateway.security.ldap.ldap1.url: ldap://ldap1.test.com:839" //
                , "georchestra.gateway.security.ldap.ldap1.baseDn: dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.rdn: ou=users,dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.searchFilter: (uid={0})" //
                , "georchestra.gateway.security.ldap.ldap1.roles.rdn: ou=roles" //
                , "georchestra.gateway.security.ldap.ldap1.roles.searchFilter: " //
                // Georchestra extended LDAP config
                , "georchestra.gateway.security.ldap.extended1.enabled: true" //
                , "georchestra.gateway.security.ldap.extended1.extended: true" //
                , "georchestra.gateway.security.ldap.extended1.url: ldap://ldap2.test.com:839" //
                , "georchestra.gateway.security.ldap.extended1.baseDn: dc=test,dc=com" //
                , "georchestra.gateway.security.ldap.extended1.users.rdn: ou=users,dc=tes,dc=com" //
                , "georchestra.gateway.security.ldap.extended1.users.searchFilter: (uid={0})" //
                , "georchestra.gateway.security.ldap.extended1.roles.rdn: ou=roles" //
                , "georchestra.gateway.security.ldap.extended1.roles.searchFilter: "//
        ).run(context -> {
            assertThat(context).getFailure()//
                    .hasStackTraceContaining("Roles searchFilter is required")//
                    .hasStackTraceContaining("ldap.[ldap1].roles.searchFilter")//
                    .hasStackTraceContaining("ldap.[extended1].roles.searchFilter");
        });
    }

    public @Test void validates_extended_orgs_rdn_is_mandatory() {
        runner.withPropertyValues(""//
                , "georchestra.gateway.security.ldap.extended1.enabled: true" //
                , "georchestra.gateway.security.ldap.extended1.extended: true" //
                , "georchestra.gateway.security.ldap.extended1.url: ldap://ldap2.test.com:839" //
                , "georchestra.gateway.security.ldap.extended1.baseDn: dc=test,dc=com" //
                , "georchestra.gateway.security.ldap.extended1.users.rdn: ou=users,dc=tes,dc=com" //
                , "georchestra.gateway.security.ldap.extended1.users.searchFilter: (uid={0})" //
                , "georchestra.gateway.security.ldap.extended1.roles.rdn: ou=roles" //
                , "georchestra.gateway.security.ldap.extended1.roles.searchFilter: " //
                , "georchestra.gateway.security.ldap.extended1.orgs.rdn: " //
        ).run(context -> {
            assertThat(context).getFailure()//
                    .hasStackTraceContaining("Organizations search base RDN is required if extended is true")//
                    .hasStackTraceContaining("ldap.[extended1].orgs.rdn");
        });
    }

    public @Test void valid_single_config_basic() {
        runner.withPropertyValues(""//
        // Basic LDAP config
                , "georchestra.gateway.security.ldap.ldap1.enabled: true" //
                , "georchestra.gateway.security.ldap.ldap1.url: ldap://ldap1.test.com:839" //
                , "georchestra.gateway.security.ldap.ldap1.baseDn: dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.rdn: ou=users,dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.searchFilter: (uid={0})" //
                , "georchestra.gateway.security.ldap.ldap1.roles.rdn: ou=roles" //
                , "georchestra.gateway.security.ldap.ldap1.roles.searchFilter: (member={0})" //
        ).run(context -> {
            assertThat(context).hasNotFailed();
            LdapConfigProperties config = context.getBean(LdapConfigProperties.class);
            assertThat(config.simpleEnabled()).hasSize(1);
            assertThat(config.extendedEnabled()).isEmpty();
            assertThat(config.activeDirectoryEnabled()).isEmpty();

            LdapServerConfig basic = config.simpleEnabled().get(0);
            assertThat(basic).hasFieldOrPropertyWithValue("name", "ldap1");
            assertThat(basic).hasFieldOrPropertyWithValue("enabled", true);
            assertThat(basic).hasFieldOrPropertyWithValue("url", "ldap://ldap1.test.com:839");
            assertThat(basic).hasFieldOrPropertyWithValue("baseDn", "dc=georchestra,dc=org");
            assertThat(basic).hasFieldOrPropertyWithValue("usersRdn", "ou=users,dc=georchestra,dc=org");
            assertThat(basic).hasFieldOrPropertyWithValue("usersSearchFilter", "(uid={0})");
            assertThat(basic).hasFieldOrPropertyWithValue("rolesRdn", "ou=roles");
            assertThat(basic).hasFieldOrPropertyWithValue("rolesSearchFilter", "(member={0})");
        });
    }

    public @Test void valid_single_config_extended() {
        runner.withPropertyValues(""//
        // Basic LDAP config
                , "georchestra.gateway.security.ldap.ldap1.enabled: true" //
                , "georchestra.gateway.security.ldap.ldap1.extended: true" //
                , "georchestra.gateway.security.ldap.ldap1.url: ldap://ldap1.test.com:839" //
                , "georchestra.gateway.security.ldap.ldap1.baseDn: dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.rdn: ou=users,dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.searchFilter: (uid={0})" //
                , "georchestra.gateway.security.ldap.ldap1.roles.rdn: ou=roles" //
                , "georchestra.gateway.security.ldap.ldap1.roles.searchFilter: (member={0})" //
                , "georchestra.gateway.security.ldap.ldap1.orgs.rdn: ou=orgs" //
        ).run(context -> {
            assertThat(context).hasNotFailed();
            LdapConfigProperties config = context.getBean(LdapConfigProperties.class);
            assertThat(config.simpleEnabled()).isEmpty();
            assertThat(config.extendedEnabled()).hasSize(1);
            assertThat(config.activeDirectoryEnabled()).isEmpty();

            ExtendedLdapConfig extended = config.extendedEnabled().get(0);
            assertThat(extended).hasFieldOrPropertyWithValue("name", "ldap1");
            assertThat(extended).hasFieldOrPropertyWithValue("enabled", true);
            assertThat(extended).hasFieldOrPropertyWithValue("url", "ldap://ldap1.test.com:839");
            assertThat(extended).hasFieldOrPropertyWithValue("baseDn", "dc=georchestra,dc=org");
            assertThat(extended).hasFieldOrPropertyWithValue("usersRdn", "ou=users,dc=georchestra,dc=org");
            assertThat(extended).hasFieldOrPropertyWithValue("usersSearchFilter", "(uid={0})");
            assertThat(extended).hasFieldOrPropertyWithValue("rolesRdn", "ou=roles");
            assertThat(extended).hasFieldOrPropertyWithValue("rolesSearchFilter", "(member={0})");
            assertThat(extended).hasFieldOrPropertyWithValue("orgsRdn", "ou=orgs");
        });
    }

    public @Test void valid_single_config_activeDirectory_minimal() {
        runner.withPropertyValues(""//
                , "georchestra.gateway.security.ldap.ad.enabled: true" //
                , "georchestra.gateway.security.ldap.ad.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad.url: ldap://test.ldap2:839" //
        ).run(context -> {
            LdapConfigProperties config = context.getBean(LdapConfigProperties.class);
            assertThat(config.simpleEnabled()).isEmpty();
            assertThat(config.extendedEnabled()).isEmpty();
            assertThat(config.activeDirectoryEnabled()).hasSize(1);

            ActiveDirectoryLdapServerConfig ad = config.activeDirectoryEnabled().get(0);
            assertThat(ad).hasFieldOrPropertyWithValue("name", "ad");
            assertThat(ad).hasFieldOrPropertyWithValue("enabled", true);
            assertThat(ad).hasFieldOrPropertyWithValue("url", "ldap://test.ldap2:839");
            assertThat(ad).hasFieldOrPropertyWithValue("domain", Optional.empty());
            assertThat(ad).hasFieldOrPropertyWithValue("rootDn", Optional.empty());
            assertThat(ad).hasFieldOrPropertyWithValue("searchFilter", Optional.empty());
        });
    }

    public @Test void valid_single_config_activeDirectory_full() {
        runner.withPropertyValues(""//
                , "georchestra.gateway.security.ldap.ad.enabled: true" //
                , "georchestra.gateway.security.ldap.ad.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad.url: ldap://test.ldap2:839" //
                , "georchestra.gateway.security.ldap.ad.domain: my.domain.com" //
                , "georchestra.gateway.security.ldap.ad.baseDn: dc=my,dc=domain,dc=com" //
                ,
                "georchestra.gateway.security.ldap.ad.users.searchFilter: (&(objectClass=user)(userPrincipalName={0}))" //
        ).run(context -> {
            LdapConfigProperties config = context.getBean(LdapConfigProperties.class);
            assertThat(config.simpleEnabled()).isEmpty();
            assertThat(config.extendedEnabled()).isEmpty();
            assertThat(config.activeDirectoryEnabled()).hasSize(1);

            ActiveDirectoryLdapServerConfig ad = config.activeDirectoryEnabled().get(0);
            assertThat(ad).hasFieldOrPropertyWithValue("name", "ad");
            assertThat(ad).hasFieldOrPropertyWithValue("enabled", true);
            assertThat(ad).hasFieldOrPropertyWithValue("url", "ldap://test.ldap2:839");
            assertThat(ad).hasFieldOrPropertyWithValue("domain", Optional.of("my.domain.com"));
            assertThat(ad).hasFieldOrPropertyWithValue("rootDn", Optional.of("dc=my,dc=domain,dc=com"));
            assertThat(ad).hasFieldOrPropertyWithValue("searchFilter",
                    Optional.of("(&(objectClass=user)(userPrincipalName={0}))"));
        });
    }

    public @Test void valid_multiple_configs() {
        runner.withPropertyValues(""//
        // Basic LDAP config
                , "georchestra.gateway.security.ldap.ldap1.enabled: true" //
                , "georchestra.gateway.security.ldap.ldap1.url: ldap://ldap1.test.com:839" //
                , "georchestra.gateway.security.ldap.ldap1.baseDn: dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.rdn: ou=users,dc=georchestra,dc=org" //
                , "georchestra.gateway.security.ldap.ldap1.users.searchFilter: (uid={0})" //
                , "georchestra.gateway.security.ldap.ldap1.roles.rdn: ou=roles" //
                , "georchestra.gateway.security.ldap.ldap1.roles.searchFilter: (member={0})" //
                // Georchestra extended LDAP config
                , "georchestra.gateway.security.ldap.extended1.enabled: true" //
                , "georchestra.gateway.security.ldap.extended1.extended: true" //
                , "georchestra.gateway.security.ldap.extended1.url: ldap://ldap2.test.com:839" //
                , "georchestra.gateway.security.ldap.extended1.baseDn: dc=test,dc=com" //
                , "georchestra.gateway.security.ldap.extended1.users.rdn: ou=users,dc=tes,dc=com" //
                , "georchestra.gateway.security.ldap.extended1.users.searchFilter: (uid={0})" //
                , "georchestra.gateway.security.ldap.extended1.roles.rdn: ou=roles" //
                , "georchestra.gateway.security.ldap.extended1.roles.searchFilter: (member={0})" //
                , "georchestra.gateway.security.ldap.extended1.orgs.rdn: ou=orgs" //
                // minimal AD config
                , "georchestra.gateway.security.ldap.ad1.enabled: true" //
                , "georchestra.gateway.security.ldap.ad1.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad1.url: ldap://test.ldap:839" //
                // full AD config
                , "georchestra.gateway.security.ldap.ad2.enabled: true" //
                , "georchestra.gateway.security.ldap.ad2.activeDirectory: true" //
                , "georchestra.gateway.security.ldap.ad2.url: ldap://test.ldap2:839" //
                , "georchestra.gateway.security.ldap.ad2.domain: my.domain.com" //
                , "georchestra.gateway.security.ldap.ad2.baseDn: dc=my,dc=domain,dc=com" //
                ,
                "georchestra.gateway.security.ldap.ad2.users.searchFilter: (&(objectClass=user)(userPrincipalName={0}))" //
        ).run(context -> {
            assertThat(context).hasNotFailed();

            LdapConfigProperties config = context.getBean(LdapConfigProperties.class);
            assertThat(config.simpleEnabled()).hasSize(1);
            assertThat(config.extendedEnabled()).hasSize(1);
            assertThat(config.activeDirectoryEnabled()).hasSize(2);
        });
    }
}
