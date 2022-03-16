package org.georchestra.gateway.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

@ConfigurationProperties(prefix = "proxy")
public @Data class ProxyConfigProperties {
    private String host;
    private Integer port;
}
