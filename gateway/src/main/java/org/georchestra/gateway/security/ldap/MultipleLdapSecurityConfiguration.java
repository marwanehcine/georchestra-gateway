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
import java.util.stream.Collectors;

import org.georchestra.gateway.security.ServerHttpSecurityCustomizer;
import org.georchestra.gateway.security.ldap.LdapConfigProperties.LdapServerConfig;
import org.georchestra.gateway.security.ldap.LdapConfigProperties.Server;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerAdapter;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetails;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

import lombok.extern.slf4j.Slf4j;

/**
 * {@link ServerHttpSecurityCustomizer} to enable LDAP based authentication and
 * authorization across multiple LDAP databases.
 * <p>
 * This configuration sets up the required beans for spring-based LDAP
 * authentication and authorization, using {@link LdapConfigProperties} to get
 * the {@link LdapConfigProperties#getUrl() connection URL} and the
 * {@link LdapConfigProperties#getBaseDn() base DN}.
 * <p>
 * As a result, the {@link ServerHttpSecurity} will have HTTP-Basic
 * authentication enabled and {@link ServerHttpSecurity#formLogin() form login}
 * set up.
 * <p>
 * Upon successful authentication, the corresponding {@link Authentication} with
 * an {@link LdapUserDetails} as {@link Authentication#getPrincipal() principal}
 * and the roles extracted from LDAP as {@link Authentication#getAuthorities()
 * authorities}, will be set as the security context's
 * {@link SecurityContext#getAuthentication() authentication} property.
 * <p>
 * Note however, this may not be enough information to convey
 * geOrchestra-specific HTTP request headers to backend services, depending on
 * the matching gateway-route configuration. See
 * {@link GeorchestraLdapAccountManagementConfiguration} for further details.
 * 
 * @see GeorchestraLdapAccountManagementConfiguration
 * @see LdapConfigProperties
 */
@Configuration(proxyBeanMethods = true)
@EnableConfigurationProperties(LdapConfigProperties.class)
@Slf4j(topic = "org.georchestra.gateway.security.ldap")
public class MultipleLdapSecurityConfiguration {

    public static final class LDAPAuthenticationCustomizer implements ServerHttpSecurityCustomizer {
        public @Override void customize(ServerHttpSecurity http) {
            log.info("Enabling HTTP Basic authentication support for LDAP");
            http.httpBasic().and().formLogin();
        }
    }

    @Bean
    public ServerHttpSecurityCustomizer ldapHttpBasicLoginFormEnablerExtension() {
        return new LDAPAuthenticationCustomizer();
    }

    @Bean
    public AuthenticationWebFilter ldapAuthenticationWebFilter(
            ReactiveAuthenticationManager ldapAuthenticationManager) {
        AuthenticationWebFilter ldapAuthFilter = new AuthenticationWebFilter(ldapAuthenticationManager);
        ldapAuthFilter.setRequiresAuthenticationMatcher(ServerWebExchangeMatchers.pathMatchers("/auth/login"));
        return ldapAuthFilter;
    }

    @Bean
    public LdapAuthenticatedUserMapper ldapAuthenticatedUserMapper() {
        return new LdapAuthenticatedUserMapper();
    }

    /**
     * @return a {@link ReactiveAuthenticationManager} that will probe
     *         username/password authentication over all configured and enabled LDAP
     *         databases in {@link LdapConfigProperties}, returning the first
     *         successful authorization.
     */
    @Bean
    public ReactiveAuthenticationManager ldapAuthenticationManager(LdapConfigProperties config) {
        List<LdapServerConfig> enabledConfigs = config.configs().stream().filter(LdapServerConfig::isEnabled)
                .collect(Collectors.toList());
        List<AuthenticationProvider> providers = enabledConfigs.stream().map(this::createLdapProvider)
                .collect(Collectors.toList());
        AuthenticationManager manager = new ProviderManager(providers);
        return new ReactiveAuthenticationManagerAdapter(manager);
    }

    private AuthenticationProvider createLdapProvider(LdapServerConfig ldapConfig) {
        log.info("Creating LDAP AuthenticationProvider for {}", ldapConfig.getUrl());
        final BaseLdapPathContextSource source = contextSource(ldapConfig);
        final BindAuthenticator authenticator = ldapAuthenticator(ldapConfig, source);
        final DefaultLdapAuthoritiesPopulator rolesPopulator = ldapAuthoritiesPopulator(ldapConfig, source);

        LdapAuthenticationProvider provider;
        if (ldapConfig.hasGeorchestraExtensions()) {
            String configName = ldapConfig.getName();
            provider = new GeorchestraLdapAuthenticationProvider(configName, authenticator, rolesPopulator);
        } else {
            provider = new LdapAuthenticationProvider(authenticator, rolesPopulator);
        }

        final GrantedAuthoritiesMapper rolesMapper = ldapAuthoritiesMapper(ldapConfig);
        provider.setAuthoritiesMapper(rolesMapper);
        return provider;
    }

    private static class GeorchestraLdapAuthenticationProvider extends LdapAuthenticationProvider {

        private String configName;

        GeorchestraLdapAuthenticationProvider(//
                String configName, //
                LdapAuthenticator authenticator, //
                LdapAuthoritiesPopulator authoritiesPopulator) {

            super(authenticator, authoritiesPopulator);
            this.configName = configName;
        }

        @Override
        public Authentication authenticate(Authentication authentication) throws AuthenticationException {
            Authentication auth = super.authenticate(authentication);
            log.debug("Authenticated {} with roles {}", auth.getName(), auth.getAuthorities());
            return new GeorchestraUserNamePasswordAuthenticationToken(configName, auth);
        }
    }

    private BindAuthenticator ldapAuthenticator(Server server, final BaseLdapPathContextSource contextSource) {
        final String ldapUserSearchBase = server.getUsers().getRdn();
        final String ldapUserSearchFilter = server.getUsers().getSearchFilter();

        FilterBasedLdapUserSearch search = new FilterBasedLdapUserSearch(ldapUserSearchBase, ldapUserSearchFilter,
                contextSource);

        BindAuthenticator authenticator = new BindAuthenticator(contextSource);
        authenticator.setUserSearch(search);
        authenticator.afterPropertiesSet();
        return authenticator;
    }

    private BaseLdapPathContextSource contextSource(LdapServerConfig server) {
        LdapContextSource context = new LdapContextSource();
        context.setUrl(server.getUrl());
        context.setBase(server.getBaseDn());
        context.afterPropertiesSet();
        return context;
    }

    private GrantedAuthoritiesMapper ldapAuthoritiesMapper(LdapServerConfig server) {
        boolean upperCase = server.getRoles().isUpperCase();
        SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
        authorityMapper.setConvertToUpperCase(upperCase);
        return authorityMapper;
    }

    private DefaultLdapAuthoritiesPopulator ldapAuthoritiesPopulator(LdapServerConfig server,
            BaseLdapPathContextSource contextSource) {

        String ldapGroupSearchBase = server.getRoles().getRdn();
        String ldapGroupSearchFilter = server.getRoles().getSearchFilter();

        DefaultLdapAuthoritiesPopulator authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(contextSource,
                ldapGroupSearchBase);
        authoritiesPopulator.setGroupSearchFilter(ldapGroupSearchFilter);

        String prefix = server.getRoles().getPrefix();
        if (null != prefix) {
            authoritiesPopulator.setRolePrefix(prefix);
        }

        return authoritiesPopulator;
    }
}
