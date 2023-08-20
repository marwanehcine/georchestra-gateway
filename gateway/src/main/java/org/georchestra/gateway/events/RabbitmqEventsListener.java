package org.georchestra.gateway.events;

import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageListener;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

@Slf4j(topic = "org.georchestra.gateway.events")
public class RabbitmqEventsListener implements MessageListener {

    public static final String OAUTH2_ACCOUNT_CREATION_RECEIVED = "OAUTH2-ACCOUNT-CREATION-RECEIVED";

    private static Set<String> synReceivedMessageUid = Collections.synchronizedSet(new HashSet<String>());

    public void onMessage(Message message) {
        String messageBody = new String(message.getBody());
        JSONObject jsonObj = new JSONObject(messageBody);
        String uid = jsonObj.getString("uid");
        String subject = jsonObj.getString("subject");
        if (subject.equals(OAUTH2_ACCOUNT_CREATION_RECEIVED)
                && !synReceivedMessageUid.stream().anyMatch(s -> s.equals(uid))) {
            String msg = jsonObj.getString("msg");
            synReceivedMessageUid.add(uid);
            log.info(msg);
        }
    }
}