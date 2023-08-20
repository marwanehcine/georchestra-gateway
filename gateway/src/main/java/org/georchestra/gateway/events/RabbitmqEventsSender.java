package org.georchestra.gateway.events;

import org.json.JSONObject;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

import java.util.UUID;

public class RabbitmqEventsSender {

    public static final String OAUTH2_ACCOUNT_CREATION = "OAUTH2-ACCOUNT-CREATION";

    @Autowired
    private ApplicationContext applicationContext;

    private AmqpTemplate eventTemplate;

    public RabbitmqEventsSender(AmqpTemplate eventTemplate) {
        this.eventTemplate = eventTemplate;
    }

    public void sendNewOAuthAccountMessage(String username, String email, String provider) throws Exception {
        // beans
        // getting a reference to
        // the sender
        JSONObject jsonObj = new JSONObject();
        jsonObj.put("uid", UUID.randomUUID());
        jsonObj.put("subject", OAUTH2_ACCOUNT_CREATION);
        jsonObj.put("username", username); // bean
        jsonObj.put("email", email); // bean
        jsonObj.put("provider", provider); // bean
        eventTemplate.convertAndSend("routing-gateway", jsonObj.toString());// send
    }
}