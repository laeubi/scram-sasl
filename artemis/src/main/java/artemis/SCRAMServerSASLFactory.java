/*
 * Copyright 2021 Christoph Läubrich
 * <p>
 * All rights reserved. Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package artemis;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.UUID;

import javax.security.auth.Subject;

import org.apache.activemq.artemis.core.server.ActiveMQServer;
import org.apache.activemq.artemis.protocol.amqp.broker.AmqpInterceptor;
import org.apache.activemq.artemis.protocol.amqp.sasl.SASLResult;
import org.apache.activemq.artemis.protocol.amqp.sasl.ServerSASL;
import org.apache.activemq.artemis.protocol.amqp.sasl.ServerSASLFactory;
import org.apache.activemq.artemis.spi.core.protocol.ProtocolManager;
import org.apache.activemq.artemis.spi.core.protocol.RemotingConnection;
import org.apache.activemq.artemis.spi.core.remoting.Connection;

import com.bolyartech.scram_sasl.server.ScramServerFunctionality;
import com.bolyartech.scram_sasl.server.ScramServerFunctionalityImpl;
import com.bolyartech.scram_sasl.server.UserData;

public abstract class SCRAMServerSASLFactory implements ServerSASLFactory {

	private String method;
	private String digestName;
	private String hmacName;

	public SCRAMServerSASLFactory(String method, String digestName, String hmacName) {
		this.method = method;
		this.digestName = digestName;
		this.hmacName = hmacName;
	}

	@Override
	public String getMechanism() {
		return method;
	}

	@Override
	public boolean isDefaultPermitted() {
		return false;
	}

	@Override
	public ServerSASL create(ActiveMQServer server, ProtocolManager<AmqpInterceptor> manager, Connection connection,
			RemotingConnection remotingConnection) {
		System.out.println("==== initiate " + method + " ====");
		return new SCRAMServerSASL(method,
				new ScramServerFunctionalityImpl(digestName, hmacName, UUID.randomUUID().toString()), getUserData());
	}

	protected abstract UserData getUserData();

	private static final class SCRAMServerSASL implements ServerSASL {

		private String name;
		private ScramServerFunctionality scram;
		private SASLResult result;
		private UserData userData;

		public SCRAMServerSASL(String name, ScramServerFunctionality scram, UserData userData) {
			this.name = name;
			this.scram = scram;
			this.userData = userData;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public byte[] processSASL(byte[] bytes) {
			String message = new String(bytes, StandardCharsets.US_ASCII);
			System.out.println("<<< " + message + " [" + scram.getState() + "]");
			try {
				switch (scram.getState()) {
				case INITIAL: {
					String userName = scram.handleClientFirstMessage(message);
					result = new SCRAMSASLResult(userName, scram);
					if (userName != null) {
						String challenge = scram.prepareFirstMessage(userData);
						System.out.println(" >>> " + challenge + " [" + scram.getState() + "]");
						return challenge.getBytes(StandardCharsets.US_ASCII);
					}
					break;
				}
				case PREPARED_FIRST: {
					String finalMessage = scram.prepareFinalMessage(message);
					if (finalMessage != null) {
						System.out.println(" >>> " + finalMessage + " [" + scram.getState() + "]");
						return finalMessage.getBytes(StandardCharsets.US_ASCII);
					}
					break;
				}

				default:
					System.out.println("???");
					break;
				}
			} catch (GeneralSecurityException e) {
				result = new SCRAMFailedSASLResult();
				e.printStackTrace();
			}
			return null;
		}

		@Override
		public SASLResult result() {
			if (result instanceof SCRAMSASLResult) {
				return scram.isEnded() ? result : null;
			}
			return result;
		}

		@Override
		public void done() {
		}

	}

	private static final class SCRAMSASLResult implements SASLResult {

		private String userName;
		private ScramServerFunctionality scram;

		public SCRAMSASLResult(String userName, ScramServerFunctionality scram) {
			this.userName = userName;
			this.scram = scram;
		}

		@Override
		public String getUser() {
			return userName;
		}

		@Override
		public Subject getSubject() {
			return null;
		}

		@Override
		public boolean isSuccess() {
			return userName != null && scram.isEnded() && scram.isSuccessful();
		}

		@Override
		public String toString() {
			return "SCRAMSASLResult: userName = " + userName + ", state = " + scram.getState();
		}

	}

	private static final class SCRAMFailedSASLResult implements SASLResult {

		@Override
		public String getUser() {
			return null;
		}

		@Override
		public Subject getSubject() {
			return null;
		}

		@Override
		public boolean isSuccess() {
			return false;
		}

		@Override
		public String toString() {
			return "SCRAMFailedSASLResult";
		}

	}

}
