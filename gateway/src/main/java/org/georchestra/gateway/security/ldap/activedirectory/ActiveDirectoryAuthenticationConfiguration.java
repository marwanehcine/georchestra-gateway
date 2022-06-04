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

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.georchestra.gateway.security.ldap.LdapConfigProperties;
import org.georchestra.gateway.security.ldap.basic.LdapAuthenticatedUserMapper;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerAdapter;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider;

import lombok.extern.slf4j.Slf4j;

/**
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(LdapConfigProperties.class)
@Slf4j(topic = "org.georchestra.gateway.security.ldap.activedirectory")
public class ActiveDirectoryAuthenticationConfiguration {

    /**
     * @return a {@link ReactiveAuthenticationManager} that will probe
     *         username/password authentication over all configured and enabled
     *         {@link LdapConfigProperties#activeDirectory() ActiveDirectory}
     *         services in {@link LdapConfigProperties}, returning the first
     *         successful authorization.
     */
    @Bean
    public ReactiveAuthenticationManager activeDirectoryAuthenticationManager(
            List<ActiveDirectoryLdapAuthenticationProvider> adProviders) {
        if (adProviders.isEmpty())
            return null;
        List<AuthenticationProvider> providers = adProviders.stream().map(AuthenticationProvider.class::cast)
                .collect(Collectors.toList());

        return new ReactiveAuthenticationManagerAdapter(new ProviderManager(providers));
    }

    @Bean
    public LdapAuthenticatedUserMapper activeDirectoryAuthenticatedUserMapper(
            List<ActiveDirectoryLdapServerConfig> enabledConfigs) {
        return enabledConfigs.isEmpty() ? null : new LdapAuthenticatedUserMapper();
    }

    @Bean
    List<ActiveDirectoryLdapServerConfig> enabledActiveDirectoryLdapConfigs(LdapConfigProperties config) {
        return config.activeDirectoryEnabled();
    }

    @Bean
    List<ActiveDirectoryLdapAuthenticationProvider> activeDirectoryLdapAuthenticationProviders(
            List<ActiveDirectoryLdapServerConfig> configs) {
        return configs.stream().map(this::activeDirectoryAuthenticationProvider).collect(Collectors.toList());
    }

    private ActiveDirectoryLdapAuthenticationProvider activeDirectoryAuthenticationProvider(
            ActiveDirectoryLdapServerConfig config) {

        final String url = config.getUrl();
        final String domain = config.getDomain().orElse(null);
        final String rootDn = config.getRootDn().orElse(null);

        // defaults to (&(objectClass=user)(userPrincipalName={0})) in
        // ActiveDirectoryLdapAuthenticationProvider
        final Optional<String> searchFilter = config.getSearchFilter();

        ActiveDirectoryLdapAuthenticationProvider adAuth = new ActiveDirectoryLdapAuthenticationProvider(domain, url,
                rootDn);
        // throw AccountStatusException subclasses, prevents the ProviderManager to
        // continue trying other providers if the account is found and
        // expired/disabled/locked
        adAuth.setConvertSubErrorCodesToExceptions(true);
        searchFilter.ifPresent(filter -> {
            log.info("Using custom search filter for Active Directory config {}: {}", config.getName(), filter);
            adAuth.setSearchFilter(filter);
        });
        return adAuth;
    }
}
