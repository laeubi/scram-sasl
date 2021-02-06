package com.bolyartech.scram_sasl.examples;

import javax.jms.Connection;
import javax.jms.ConnectionFactory;
import javax.jms.JMSException;
import javax.jms.MessageConsumer;
import javax.jms.MessageProducer;
import javax.jms.Queue;
import javax.jms.Session;
import javax.jms.TextMessage;

import org.apache.qpid.jms.JmsConnectionFactory;

public class QPIDClient {
	public static void main(String[] args) throws JMSException {
		for (String method : new String[] { "SCRAM-SHA-256" }) {
			ConnectionFactory connectionFactory = new JmsConnectionFactory(
					"amqp://localhost:5672?amqp.saslMechanisms=" + method);
			Connection connection = connectionFactory.createConnection("hello", "ogre1234");
			try {
				Session session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
				Queue queue = session.createQueue("exampleQueue");
				MessageProducer sender = session.createProducer(queue);
				sender.send(session.createTextMessage("Hello " + method));
				connection.start();
				MessageConsumer consumer = session.createConsumer(queue);
				TextMessage m = (TextMessage) consumer.receive(5000);
				System.out.println("message = " + m.getText());
			} finally {
				connection.close();
			}
		}
	}
}
