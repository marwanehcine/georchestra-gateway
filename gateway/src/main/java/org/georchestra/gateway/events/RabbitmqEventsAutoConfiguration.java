package org.georchestra.gateway.events;

import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.listener.MessageListenerContainer;
import org.springframework.amqp.rabbit.listener.SimpleMessageListenerContainer;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.amqp.core.Queue;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.cloud.gateway.config.GatewayAutoConfiguration;
import org.springframework.context.annotation.*;

@Profile("!test && !it")
@Configuration(proxyBeanMethods = false)
@AutoConfigureAfter(GatewayAutoConfiguration.class)
@ImportResource({ "classpath:rabbit-listener-context.xml", "classpath:rabbit-sender-context.xml" })
@ConditionalOnExpression("${georchestra.gateway.security.enableRabbitmqEvents:true}")
public class RabbitmqEventsAutoConfiguration {

    @Bean
    @DependsOn({ "eventTemplate" })
    public RabbitmqEventsSender eventsSender(AmqpTemplate eventTemplate) {
        return new RabbitmqEventsSender(eventTemplate);
    }

    Queue OAuth2ReplyQueue() {
        return new Queue("OAuth2ReplyQueue", false);
    }

    MessageListenerContainer messageListenerContainer(ConnectionFactory connectionFactory) {
        SimpleMessageListenerContainer simpleMessageListenerContainer = new SimpleMessageListenerContainer();
        simpleMessageListenerContainer.setConnectionFactory(connectionFactory);
        simpleMessageListenerContainer.setQueues(OAuth2ReplyQueue());
        simpleMessageListenerContainer.setMessageListener(new RabbitmqEventsListener());
        return simpleMessageListenerContainer;
    }
}