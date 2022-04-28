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

import static org.assertj.core.api.Assertions.assertThat;

import org.georchestra.gateway.security.oauth2.OAuth2Configuration.OAuth2AuthenticationCustomizer;
import org.georchestra.gateway.security.oauth2.OAuth2ProxyConfigProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;

/**
 * Assert context contributions of {@link OAuth2SecurityAutoConfiguration}
 *
 */
class OAuth2SecurityAutoConfigurationTest {
    private ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(OAuth2SecurityAutoConfiguration.class));

    @Test
    void testDisabledByDefault() {
        testDisabled(runner);
    }

    @Test
    void testDisabledExplicitly() {
        testDisabled(runner.withPropertyValues("georchestra.gateway.security.oauth2.enabled=false"));
    }

    @Test
    void testEnabled() {
        runner.withPropertyValues(//
                "georchestra.gateway.security.oauth2.enabled=true")//
                .run(context -> {

                    assertThat(context).hasSingleBean(OAuth2ProxyConfigProperties.class);
                    assertThat(context).hasSingleBean(OAuth2AuthenticationCustomizer.class);
                    assertThat(context).hasSingleBean(ReactiveOAuth2AccessTokenResponseClient.class);
                    assertThat(context).hasSingleBean(DefaultReactiveOAuth2UserService.class);
                    assertThat(context).hasSingleBean(OidcReactiveOAuth2UserService.class);
                    assertThat(context).hasBean("oauth2WebClient");
                    assertThat(context).hasBean("oAuth2AuthenticationTokenUserMapper");
                    assertThat(context).hasBean("oAuth2AuthenticationTokenOpenIDUserMapper");
                });
        ;
    }

    private void testDisabled(ApplicationContextRunner runner) {
        runner.run(context -> {
            assertThat(context).doesNotHaveBean(OAuth2ProxyConfigProperties.class);
            assertThat(context).doesNotHaveBean(OAuth2AuthenticationCustomizer.class);
            assertThat(context).doesNotHaveBean(ReactiveOAuth2AccessTokenResponseClient.class);
            assertThat(context).doesNotHaveBean(ReactiveOAuth2UserService.class);
            assertThat(context).doesNotHaveBean("oauth2WebClient");
            assertThat(context).doesNotHaveBean("oAuth2AuthenticationTokenUserMapper");
            assertThat(context).doesNotHaveBean("oAuth2AuthenticationTokenOpenIDUserMapper");
        });
    }
}
