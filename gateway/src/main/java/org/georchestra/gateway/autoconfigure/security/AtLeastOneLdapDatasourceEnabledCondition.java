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

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionMessage.ItemsBuilder;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.AbstractEnvironment;
import org.springframework.core.env.EnumerablePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.type.AnnotatedTypeMetadata;

import com.google.common.collect.Streams;

import lombok.extern.slf4j.Slf4j;

/**
 *
 */
@Slf4j
class AtLeastOneLdapDatasourceEnabledCondition extends SpringBootCondition {

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
        Environment environment = context.getEnvironment();
        MutablePropertySources propertySources = ((AbstractEnvironment) environment).getPropertySources();

        final String regex = "georchestra\\.gateway\\.security\\.ldap\\.(.*)\\.enabled";
        final Pattern pattern = Pattern.compile(regex);
        final Predicate<String> propertyNameFilter = pattern.asMatchPredicate();

        final List<String> patternMatches = new ArrayList<>();

        final boolean anyMatch = Streams.stream(propertySources)//
                .filter(EnumerablePropertySource.class::isInstance)//
                .map(EnumerablePropertySource.class::cast)//
                .map(EnumerablePropertySource::getPropertyNames)//
                .flatMap(Stream::of)//
                .filter(propertyNameFilter)//
                .peek(p -> {
                    log.debug("checking if LDAP config is enabled for {}", p);
                    patternMatches.add(p);
                })//
                .map(environment::getProperty)//
                .map(Boolean::valueOf)//
                .anyMatch(enabled -> enabled);

        if (anyMatch) {
            return ConditionOutcome.match();
        }

        ItemsBuilder itemsBuilder = ConditionMessage.forCondition(ConditionalOnLdapEnabled.class)
                .didNotFind("any enabled ldap config");

        ConditionMessage message;
        if (patternMatches.isEmpty()) {
            message = itemsBuilder.atAll();
        } else {
            message = itemsBuilder.items(patternMatches);
        }

        return ConditionOutcome.noMatch(message);
    }

}
