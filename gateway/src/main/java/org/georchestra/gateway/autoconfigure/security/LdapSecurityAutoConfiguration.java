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

import javax.annotation.PostConstruct;

import org.georchestra.gateway.security.ldap.LdapAccountManagementConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.ldap.core.LdapTemplate;

import lombok.extern.slf4j.Slf4j;

@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(LdapTemplate.class)
@Import({ LdapSecurityAutoConfiguration.Enabled.class, LdapSecurityAutoConfiguration.Disabled.class })
@Slf4j(topic = "org.georchestra.gateway.autoconfigure.security")
public class LdapSecurityAutoConfiguration {

    private static final String ENABLED_PROP = "georchestra.gateway.security.ldap.enabled";

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(name = ENABLED_PROP, havingValue = "true", matchIfMissing = false)
    @Import({ org.georchestra.gateway.security.ldap.LdapSecurityConfiguration.class,
            LdapAccountManagementConfiguration.class })
    static class Enabled {

        public @PostConstruct void log() {
            log.info("georchestra LDAP security enabled");
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnProperty(name = ENABLED_PROP, havingValue = "false", matchIfMissing = true)
    static class Disabled {

        public @PostConstruct void log() {
            log.info("georchestra LDAP security disabled");
        }
    }
}
