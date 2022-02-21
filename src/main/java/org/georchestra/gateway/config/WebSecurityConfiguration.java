package org.georchestra.gateway.config;

import org.springframework.context.annotation.Bean;
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

@EnableWebFluxSecurity
public class WebSecurityConfiguration {

    public HttpClient proxyHttpClient() {
        String proxyHost = System.getProperty("https.proxyHost");
        String proxyPort = System.getProperty("https.proxyPort");

        if (proxyHost == null && proxyPort == null) {
            return HttpClient.create();
        }

        return HttpClient.create().tcpConfiguration(tcpClient -> tcpClient
                .proxy(proxy -> proxy.type(ProxyProvider.Proxy.HTTP).host(proxyHost).port(Integer.valueOf(proxyPort))));
    }

    @Bean
    public ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
            ReactiveClientRegistrationRepository clientRegistrationRepository,
            ReactiveOAuth2AuthorizedClientService authorizedClientService) {

        return configureHttpProxy(new AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager(
                clientRegistrationRepository, authorizedClientService));
    }

    private AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager configureHttpProxy(
            AuthorizedClientServiceReactiveOAuth2AuthorizedClientManager authorizedClientManager) {
        WebClientReactiveClientCredentialsTokenResponseClient tokenResponseClient = new WebClientReactiveClientCredentialsTokenResponseClient();
        tokenResponseClient.setWebClient(
                WebClient.builder().clientConnector(new ReactorClientHttpConnector(proxyHttpClient())).build());

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