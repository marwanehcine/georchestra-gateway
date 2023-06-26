package org.georchestra.gateway.security.oauth2;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties(prefix = "spring.security.oauth2.client")
public class ExtendedOAuth2ClientProperties implements InitializingBean {

    private final Map<String, Provider> provider = new HashMap<>();

    public Map<String, Provider> getProvider() {
        return this.provider;
    }

    public static class Provider extends OAuth2ClientProperties.Provider {
        private String endSessionUri;

        public String getEndSessionUri() {
            return this.endSessionUri;
        }

        public void setEndSessionUri(String endSessionUri) {
            this.endSessionUri = endSessionUri;
        }
    }

    @Override
    public void afterPropertiesSet() {
    }
}
