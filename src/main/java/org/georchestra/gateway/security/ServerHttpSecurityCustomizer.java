package org.georchestra.gateway.security;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;

public interface ServerHttpSecurityCustomizer extends Customizer<ServerHttpSecurity> {

    default String getName() {
        return getClass().getCanonicalName();
    }
}
