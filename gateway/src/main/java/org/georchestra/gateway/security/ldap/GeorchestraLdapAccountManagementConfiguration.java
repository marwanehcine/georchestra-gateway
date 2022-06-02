package org.georchestra.gateway.security.ldap;

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

import static java.util.Objects.requireNonNull;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.georchestra.ds.orgs.OrgsDao;
import org.georchestra.ds.orgs.OrgsDaoImpl;
import org.georchestra.ds.roles.RoleDao;
import org.georchestra.ds.roles.RoleDaoImpl;
import org.georchestra.ds.roles.RoleProtected;
import org.georchestra.ds.security.UserMapper;
import org.georchestra.ds.security.UserMapperImpl;
import org.georchestra.ds.security.UsersApiImpl;
import org.georchestra.ds.users.AccountDao;
import org.georchestra.ds.users.AccountDaoImpl;
import org.georchestra.ds.users.UserRule;
import org.georchestra.gateway.security.GeorchestraUserMapperExtension;
import org.georchestra.gateway.security.ldap.LdapConfigProperties.Organizations;
import org.georchestra.gateway.security.ldap.LdapConfigProperties.Roles;
import org.georchestra.gateway.security.ldap.LdapConfigProperties.Server;
import org.georchestra.gateway.security.ldap.LdapConfigProperties.Users;
import org.georchestra.security.api.UsersApi;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.beans.factory.BeanInitializationException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

/**
 * Sets up a {@link GeorchestraUserMapperExtension} that knows how to map an
 * authentication credentials given by a
 * {@link GeorchestraUserNamePasswordAuthenticationToken} with an
 * {@link LdapUserDetails} (i.e., if the user authenticated with LDAP), to a
 * {@link GeorchestraUser}, making use of geOrchestra's
 * {@literal georchestra-ldap-account-management} module's {@link UsersApi}.
 */
@Configuration(proxyBeanMethods = false)
public class GeorchestraLdapAccountManagementConfiguration {

    @Bean
    public GeorchestraLdapAuthenticatedUserMapper georchestraLdapAuthenticatedUserMapper(DemultiplexingUsersApi users) {
        return new GeorchestraLdapAuthenticatedUserMapper(users);
    }

    @Bean
    public DemultiplexingUsersApi demultiplexingUsersApi(LdapConfigProperties config) {

        Map<String, Server> ldapExtendedConfigs = config.getLdap().entrySet().stream()
                .filter(e -> e.getValue().isEnabled())//
                .filter(e -> e.getValue().hasGeorchestraExtensions())//
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        Map<String, UsersApi> targets = new HashMap<>();
        ldapExtendedConfigs.forEach((name, ldapConfig) -> {
            UsersApi target;
            try {
                target = createUsersApi(ldapConfig);
            } catch (Exception ex) {
                throw new BeanInitializationException("Error creating georchestra users api for ldap config " + name,
                        ex);
            }
            targets.put(name, target);
        });
        return new DemultiplexingUsersApi(targets);
    }

    //////////////////////////////////////////////
    /// Low level LDAP account management beans
    //////////////////////////////////////////////

    private UsersApi createUsersApi(Server ldapConfig) throws Exception {
        final LdapTemplate ldapTemplate = ldapTemplate(ldapConfig);
        final AccountDao accountsDao = accountsDao(ldapTemplate, ldapConfig);
        final RoleDao roleDao = roleDao(ldapTemplate, ldapConfig, accountsDao);

        final UserMapper ldapUserMapper = createUserMapper(roleDao);
        UserRule userRule = ldapUserRule(ldapConfig);

        UsersApiImpl impl = new UsersApiImpl();
        impl.setAccountsDao(accountsDao);
        impl.setMapper(ldapUserMapper);
        impl.setUserRule(userRule);
        return impl;
    }

    private UserMapper createUserMapper(RoleDao roleDao) {
        UserMapperImpl impl = new UserMapperImpl();
        impl.setRoleDao(roleDao);
        return impl;
    }

    private LdapTemplate ldapTemplate(Server server) throws Exception {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(server.getUrl());
        contextSource.setBase(server.getBaseDn());
        contextSource.afterPropertiesSet();

        LdapTemplate ldapTemplate = new LdapTemplate(contextSource);
        ldapTemplate.afterPropertiesSet();
        return ldapTemplate;
    }

    private AccountDao accountsDao(LdapTemplate ldapTemplate, Server ldapConfig) {
        Users usersConfig = ldapConfig.getUsers();
        requireNonNull(usersConfig);

        Roles rolesConfig = ldapConfig.getRoles();
        requireNonNull(rolesConfig);

        String baseDn = ldapConfig.getBaseDn();
        String userSearchBaseDN = usersConfig.getRdn();
        String roleSearchBaseDN = rolesConfig.getRdn();
        String pendingUsersSearchBaseDN = usersConfig.getPendingUsersSearchBaseDN();

        AccountDaoImpl impl = new AccountDaoImpl(ldapTemplate);
        impl.setBasePath(baseDn);
        impl.setUserSearchBaseDN(userSearchBaseDN);
        impl.setRoleSearchBaseDN(roleSearchBaseDN);
        if (pendingUsersSearchBaseDN != null) {
            impl.setPendingUserSearchBaseDN(pendingUsersSearchBaseDN);
        }

        Organizations orgsConfig = ldapConfig.getOrgs();
        if (orgsConfig != null) {
            String orgSearchBaseDN = orgsConfig.getRdn();
            String pendingOrgSearchBaseDN = orgsConfig.getPendingOrgSearchBaseDN();
            impl.setOrgSearchBaseDN(orgSearchBaseDN);
            impl.setPendingOrgSearchBaseDN(pendingOrgSearchBaseDN);
        }

        impl.init();
        return impl;
    }

    private RoleDao roleDao(LdapTemplate ldapTemplate, Server ldapConfig, AccountDao accountDao) {
        String rolesRdn = ldapConfig.getRoles().getRdn();

        RoleDaoImpl impl = new RoleDaoImpl();
        impl.setLdapTemplate(ldapTemplate);
        impl.setRoleSearchBaseDN(rolesRdn);
        impl.setAccountDao(accountDao);
        impl.setRoles(ldapProtectedRoles(ldapConfig));
        return impl;
    }

    @SuppressWarnings("unused")
    private OrgsDao orgsDao(LdapTemplate ldapTemplate, Server ldapConfig) {
        OrgsDaoImpl impl = new OrgsDaoImpl();
        impl.setLdapTemplate(ldapTemplate);
        impl.setBasePath(ldapConfig.getBaseDn());
        impl.setOrgSearchBaseDN(ldapConfig.getOrgs().getRdn());
        impl.setPendingOrgSearchBaseDN(ldapConfig.getOrgs().getPendingOrgSearchBaseDN());
        impl.setOrgTypeValues(ldapConfig.getOrgs().getOrgTypes());
        return impl;
    }

    private UserRule ldapUserRule(Server ldapConfig) {
        Users users = ldapConfig.getUsers();
        List<String> protectedUsers = users.getProtectedUsers();
        UserRule rule = new UserRule();
        rule.setListOfprotectedUsers(protectedUsers.toArray(String[]::new));
        return rule;
    }

    private RoleProtected ldapProtectedRoles(Server ldapConfig) {
        Roles roles = ldapConfig.getRoles();
        List<String> protectedRoles = roles.getProtectedRoles();
        RoleProtected bean = new RoleProtected();
        bean.setListOfprotectedRoles(protectedRoles.toArray(String[]::new));
        return bean;
    }

}
