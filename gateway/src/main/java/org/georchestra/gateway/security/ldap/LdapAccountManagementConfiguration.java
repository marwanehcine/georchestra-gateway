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

import org.georchestra.ds.orgs.OrgsDao;
import org.georchestra.ds.orgs.OrgsDaoImpl;
import org.georchestra.ds.roles.RoleDao;
import org.georchestra.ds.roles.RoleDaoImpl;
import org.georchestra.ds.roles.RoleProtected;
import org.georchestra.ds.security.UsersApiImpl;
import org.georchestra.ds.users.AccountDao;
import org.georchestra.ds.users.AccountDaoImpl;
import org.georchestra.ds.users.UserRule;
import org.georchestra.gateway.security.GeorchestraUserMapperExtension;
import org.georchestra.security.api.OrganizationsApi;
import org.georchestra.security.api.RolesApi;
import org.georchestra.security.api.UsersApi;
import org.georchestra.security.model.GeorchestraUser;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.ldap.userdetails.LdapUserDetails;

/**
 * Sets up a {@link GeorchestraUserMapperExtension} that knows how to map an
 * authentication credentials given by a
 * {@link UsernamePasswordAuthenticationToken} with an {@link LdapUserDetails}
 * (i.e., if the user authenticated with LDAP), to a {@link GeorchestraUser},
 * making use of geOrchestra's {@literal georchestra-ldap-account-management}
 * module's {@link UsersApi}.
 */
@Configuration(proxyBeanMethods = false)
@ComponentScan(basePackageClasses = UsersApiImpl.class)
public class LdapAccountManagementConfiguration {

    //////////////////////////////////////////////
    /// High level accounts API beans
    //////////////////////////////////////////////
//
//	public @Bean UsersApi ldapUsersAPI() {
//		return new UsersApiImpl();
//	}
//
//	public @Bean OrganizationsApi ldapOrganizationsAPI() {
//		return new OrganizationsApiImpl();
//	}
//
//	public @Bean RolesApi ldapRolesAPI() {
//		return new RolesApiImpl();
//	}

    @Bean
    LdapAuthenticatedUserMapper ldapAuthenticatedUserMapperExtension(//
            UsersApi users, //
            OrganizationsApi orgs, //
            RolesApi roles) {
        return new LdapAuthenticatedUserMapper(users);
    }

    //////////////////////////////////////////////
    /// Low level LDAP account management beans
    //////////////////////////////////////////////

    @Bean
    LdapTemplate defaultGeorchestraLdapTemplate(ContextSource contextSource) {
        return new LdapTemplate(contextSource);
    }

//	  <bean id="accountDao" class="org.georchestra.ds.users.AccountDaoImpl">
//    <constructor-arg ref="ldapTemplate"/>
//    <property name="basePath" value="${ldapBaseDn}"/>
//    <property name="userSearchBaseDN" value="${ldapUsersRdn}"/>
//    <property name="pendingUserSearchBaseDN" value="${pendingUserSearchBaseDN:ou=pendingusers}"/>
//    <property name="orgSearchBaseDN" value="${ldapOrgsRdn}"/>
//    <property name="pendingOrgSearchBaseDN" value="${pendingOrgSearchBaseDN:ou=pendingorgs}"/>
//    <property name="roleSearchBaseDN" value="${ldapRolesRdn}"/>
//  </bean>
    @Bean
    AccountDao accountDao(@Qualifier("defaultGeorchestraLdapTemplate") LdapTemplate ldapTemplate,
            LdapConfigProperties config) {

        AccountDaoImpl impl = new AccountDaoImpl(ldapTemplate);
        impl.setBasePath(config.getBaseDn());
        impl.setUserSearchBaseDN(config.getUsersRdn());
        impl.setOrgSearchBaseDN(config.getOrgsRdn());
        impl.setRoleSearchBaseDN(config.getRolesRdn());
        // REVISIT add to config?
        impl.setPendingOrgSearchBaseDN("ou=pendingusers");
        impl.setPendingOrgSearchBaseDN("ou=pendingorgs");
        return impl;
    }

//	  <bean id="roleDao" class="org.georchestra.ds.roles.RoleDaoImpl">
//	    <property name="ldapTemplate" ref="ldapTemplate"/>
//	    <property name="roleSearchBaseDN" value="${ldapRolesRdn}"/>
//	  </bean>
    @Bean
    RoleDao roleDao(@Qualifier("defaultGeorchestraLdapTemplate") LdapTemplate ldapTemplate,
            LdapConfigProperties config) {

        RoleDaoImpl impl = new RoleDaoImpl();
        impl.setLdapTemplate(ldapTemplate);
        String rolesRdn = config.getRolesRdn();
        impl.setRoleSearchBaseDN(rolesRdn);
        return impl;
    }

//
//	  <bean id="orgsDao" class="org.georchestra.ds.orgs.OrgsDaoImpl">
//	    <property name="ldapTemplate" ref="ldapTemplate"/>
//	    <property name="basePath" value="${ldapBaseDn}"/>
//	    <property name="orgTypeValues" value="${orgTypeValues:Association,Company,NGO,Individual,Other}"/>
//	    <property name="orgSearchBaseDN" value="${ldapOrgsRdn}"/>
//	    <property name="pendingOrgSearchBaseDN" value="${pendingOrgSearchBaseDN:ou=pendingorgs}"/>
//	  </bean>
    @Bean
    OrgsDao orgsDao(@Qualifier("defaultGeorchestraLdapTemplate") LdapTemplate ldapTemplate,
            LdapConfigProperties config) {

        OrgsDaoImpl impl = new OrgsDaoImpl();
        impl.setLdapTemplate(ldapTemplate);
        impl.setBasePath(config.getBaseDn());
        impl.setOrgSearchBaseDN(config.getOrgsRdn());
        impl.setPendingOrgSearchBaseDN(config.getPendingOrgSearchBaseDN());
        impl.setOrgTypeValues(config.getOrgTypeValues());
        return impl;
    }

//	  <bean class="org.georchestra.ds.users.UserRule">
//	    <property name="listOfprotectedUsers">
//	      <description>Comma separated list of one or more user identifiers (uid) of protected user</description>
//	        <!-- Users are defined as a comma separated list of uid and can be overridden in data dir with "protectedUsersList" key-->
//	        <value>${protectedUsersList:geoserver_privileged_user}</value>
//	    </property>
//	  </bean>
    @Bean
    UserRule ldapUserRule(LdapConfigProperties config) {
        UserRule rule = new UserRule();
        rule.setListOfprotectedUsers(config.getProtectedUsersList().toArray(String[]::new));
        return rule;
    }

//	  <bean class="org.georchestra.ds.roles.RoleProtected">
//	    <property name="listOfprotectedRoles">
//	      <description>Comma separated list of one or more protected Roles</description>
//	        <!-- Roles are defined as a comma separated list of Roles name and can be override in data dir with "protectedRolesList" key-->
//	      <value>${protectedRolesList:ADMINISTRATOR,EXTRACTORAPP,GN_.*,ORGADMIN,REFERENT,USER,SUPERUSER}</value>
//	    </property>
//	  </bean>
    @Bean
    RoleProtected ldapProtectedRoles(LdapConfigProperties config) {
        RoleProtected bean = new RoleProtected();
        bean.setListOfprotectedRoles(config.getProtectedRolesList().toArray(String[]::new));
        return bean;
    }

}
