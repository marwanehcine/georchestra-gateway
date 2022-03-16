package org.georchestra.gateway.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.oauth2.client.AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ClientCredentialsReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.netty.http.client.HttpClient;
import reactor.netty.transport.ProxyProvider;

@Configuration(proxyBeanMethods = true)
@EnableConfigurationProperties(ProxyConfigProperties.class)
@EnableWebFluxSecurity
public class WebSecurityConfiguration {

    private @Autowired ProxyConfigProperties proxyConfig;

    public HttpClient proxyHttpClient() {

        String proxyHost = proxyConfig.getHost();
        Integer proxyPort = proxyConfig.getPort();

        HttpClient httpClient = HttpClient.create();

        if (proxyHost != null && proxyPort != null) {
            httpClient = httpClient.tcpConfiguration(tcpClient -> tcpClient
                    .proxy(proxy -> proxy.type(ProxyProvider.Proxy.HTTP).host(proxyHost).port(proxyPort)));
        }
        return httpClient;
    }

    @Bean
    public ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            ReactiveOAuth2AuthorizedClientService authorizedClientService) {

        AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager = new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientService);

        return configureHttpProxy(authorizedClientManager);
    }

    private AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager configureHttpProxy(
            AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager) {

        WebClientReactiveClientCredentialsTokenResponseClient tokenResponseClient = new WebClientReactiveClientCredentialsTokenResponseClient();
        HttpClient proxyHttpClient = proxyHttpClient();
        ReactorClientHttpConnector connector = new ReactorClientHttpConnector(proxyHttpClient);
        tokenResponseClient.setWebClient(WebClient.builder().clientConnector(connector).build());

        // set the ReactiveOAuth2AccessTokenResponseClient with webclient configuration
        // in the ReactiveOAuth2AuthorizedClientProvider
        ClientCredentialsReactiveOAuth2AuthorizedClientProvider authorizedClientProvider = new ClientCredentialsReactiveOAuth2AuthorizedClientProvider();
        authorizedClientProvider.setAccessTokenResponseClient(tokenResponseClient);

        // set the ReactiveOAuth2AuthorizedClientProvider in the
        // ReactiveOAuth2AuthorizedClientManager
        authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

        return authorizedClientManager;
    }
}