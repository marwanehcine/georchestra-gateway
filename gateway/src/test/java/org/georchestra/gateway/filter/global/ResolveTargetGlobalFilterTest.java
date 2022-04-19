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

package org.georchestra.gateway.filter.global;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.georchestra.gateway.model.GatewayConfigProperties;
import org.georchestra.gateway.model.GeorchestraTargetConfig;
import org.georchestra.gateway.model.HeaderMappings;
import org.georchestra.gateway.model.RoleBasedAccessRule;
import org.georchestra.gateway.model.Service;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Test suite for {@link ResolveTargetGlobalFilter}
 *
 */
class ResolveTargetGlobalFilterTest {

    private GatewayConfigProperties config;
    private ResolveTargetGlobalFilter filter;

    private GatewayFilterChain mockChain;
    private MockServerHttpRequest request;
    private MockServerWebExchange exchange;

    final URI matchedURI = URI.create("http://fake.backend.com:8080");
    private Route matchedRoute;

    HeaderMappings defaultHeaders;
    List<RoleBasedAccessRule> defaultRules;

    @BeforeEach
    void setUp() throws Exception {
        config = new GatewayConfigProperties();
        defaultHeaders = new HeaderMappings().enableAll();
        defaultRules = List.of(rule("/global/1"));
        config.setDefaultHeaders(defaultHeaders);
        config.setGlobalAccessRules(defaultRules);

        filter = new ResolveTargetGlobalFilter(config);

        matchedRoute = mock(Route.class);
        when(matchedRoute.getUri()).thenReturn(matchedURI);

        mockChain = mock(GatewayFilterChain.class);
        when(mockChain.filter(any())).thenReturn(Mono.empty());
        request = MockServerHttpRequest.get("/test").build();
        exchange = MockServerWebExchange.from(request);
        exchange.getAttributes().put(GATEWAY_ROUTE_ATTR, matchedRoute);

    }

    @Test
    void filter_SavesResolvedTargetConfig() {
        assertTrue(GeorchestraTargetConfig.getTarget(exchange).isEmpty());
        filter.filter(exchange, mockChain);
        assertTrue(GeorchestraTargetConfig.getTarget(exchange).isPresent());
        verify(mockChain, times(1)).filter(same(exchange));
    }

    @Test
    void resolveTarget_defaultsToGlobal() {
        GeorchestraTargetConfig target = filter.resolveTarget(matchedRoute);
        assertNotNull(target);
        assertSame(defaultHeaders, target.headers());
        assertSame(defaultRules, target.accessRules());
    }

    @Test
    void resolveTarget_applies_global_headers_if_service_doesnt_define_them() {
        Service serviceWithNoHeaderMappings = service(matchedURI, (HeaderMappings) null);
        RoleBasedAccessRule serviceSpecificRule = rule("/rule/path");
        serviceWithNoHeaderMappings.setAccessRules(List.of(serviceSpecificRule));

        Service service2 = service(URI.create("https://backend.service.2"), new HeaderMappings());
        config.setServices(Map.of("service1", serviceWithNoHeaderMappings, "service2", service2));

        GeorchestraTargetConfig target = filter.resolveTarget(matchedRoute);
        assertSame(defaultHeaders, target.headers());
        assertEquals(List.of(serviceSpecificRule), target.accessRules());
    }

    @Test
    void resolveTarget_applies_global_access_rules_if_service_doesnt_define_them() {
        Service serviceWithNoAccessRules = service(matchedURI);
        HeaderMappings serviceHeaders = new HeaderMappings();
        serviceWithNoAccessRules.setHeaders(Optional.of(serviceHeaders));

        Service service2 = service(URI.create("https://backend.service.2"), new HeaderMappings());
        config.setServices(Map.of("service1", serviceWithNoAccessRules, "service2", service2));

        GeorchestraTargetConfig target = filter.resolveTarget(matchedRoute);
        assertEquals(defaultRules, target.accessRules());
        assertSame(serviceHeaders, target.headers());
    }

    private Service service(URI targetURI) {
        return service(targetURI, null);
    }

    private Service service(URI targetURI, HeaderMappings headers) {
        Service service = new Service();
        service.setTarget(targetURI);
        service.setHeaders(Optional.ofNullable(headers));
        return service;
    }

    private RoleBasedAccessRule rule(String... uris) {
        return new RoleBasedAccessRule().setInterceptUrl(Arrays.asList(uris));
    }
}
