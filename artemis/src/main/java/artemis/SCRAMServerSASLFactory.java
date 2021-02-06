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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.UUID;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;

import org.apache.activemq.artemis.core.server.ActiveMQServer;
import org.apache.activemq.artemis.protocol.amqp.broker.AmqpInterceptor;
import org.apache.activemq.artemis.protocol.amqp.broker.ProtonProtocolManager;
import org.apache.activemq.artemis.protocol.amqp.sasl.SASLResult;
import org.apache.activemq.artemis.protocol.amqp.sasl.ServerSASL;
import org.apache.activemq.artemis.protocol.amqp.sasl.ServerSASLFactory;
import org.apache.activemq.artemis.spi.core.protocol.ProtocolManager;
import org.apache.activemq.artemis.spi.core.protocol.RemotingConnection;
import org.apache.activemq.artemis.spi.core.remoting.Connection;

import com.bolyartech.scram_sasl.common.ScramException;
import com.bolyartech.scram_sasl.server.ScramServerFunctionality;
import com.bolyartech.scram_sasl.server.ScramServerFunctionalityImpl;
import com.bolyartech.scram_sasl.server.UserData;

import artemis.jaas.DigestCallback;
import artemis.jaas.HmacCallback;
import artemis.jaas.SCRAMMechanismCallback;

public abstract class SCRAMServerSASLFactory implements ServerSASLFactory {

	private SCRAM scramType;

	public SCRAMServerSASLFactory(SCRAM scram) {
		this.scramType = scram;
	}

	@Override
	public String getMechanism() {
		return scramType.getName();
	}

	@Override
	public boolean isDefaultPermitted() {
		return false;
	}

	@Override
	public ServerSASL create(ActiveMQServer server, ProtocolManager<AmqpInterceptor> manager, Connection connection,
			RemotingConnection remotingConnection) {
		try {
			if (manager instanceof ProtonProtocolManager) {
				ScramServerFunctionalityImpl scram = new ScramServerFunctionalityImpl(scramType.getDigest(),
						scramType.getHmac(),
						UUID.randomUUID().toString());
				String loginConfigScope = ((ProtonProtocolManager) manager).getSaslLoginConfigScope();
				return new SCRAMServerSASL(scramType.getName(), scram, loginConfigScope);
			}
		} catch (NoSuchAlgorithmException e) {
			// can't be used then...
		}
		return null;
	}

	private static final class SCRAMServerSASL implements ServerSASL {

		private String name;
		private ScramServerFunctionality scram;
		private SASLResult result;
		private String loginConfigScope;

		public SCRAMServerSASL(String name, ScramServerFunctionality scram, String loginConfigScope) {
			this.name = name;
			this.scram = scram;
			this.loginConfigScope = loginConfigScope;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public byte[] processSASL(byte[] bytes) {
			String message = new String(bytes, StandardCharsets.US_ASCII);
			try {
				switch (scram.getState()) {
				case INITIAL: {
					String userName = scram.handleClientFirstMessage(message);
					if (userName != null) {

						LoginContext loginContext = new LoginContext(loginConfigScope, new CallbackHandler() {

							@Override
							public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
								for (Callback callback : callbacks) {
									if (callback instanceof NameCallback) {
										((NameCallback) callback).setName(userName);
									} else if (callback instanceof SCRAMMechanismCallback) {
										((SCRAMMechanismCallback) callback).setMechanism(name);
									} else if (callback instanceof DigestCallback) {
										((DigestCallback) callback).setDigest(scram.getDigest());
									} else if (callback instanceof HmacCallback) {
										((HmacCallback) callback).setHmac(scram.getHmac());
									} else {
										throw new UnsupportedCallbackException(callback,
												"Unrecognized Callback " + callback.getClass().getSimpleName());
									}
								}
							}
						});
						loginContext.login();
						Subject subject = loginContext.getSubject();
						Iterator<UserData> credentials = subject.getPublicCredentials(UserData.class).iterator();
						if (credentials.hasNext()) {
							result = new SCRAMSASLResult(userName, scram, subject);
							String challenge = scram.prepareFirstMessage(credentials.next());
							return challenge.getBytes(StandardCharsets.US_ASCII);
						}
					}
					break;
				}
				case PREPARED_FIRST: {
					String finalMessage = scram.prepareFinalMessage(message);
					if (finalMessage != null) {
						return finalMessage.getBytes(StandardCharsets.US_ASCII);
					}
					break;
				}

				default:
					result = new SCRAMFailedSASLResult();
					break;
				}
			} catch (GeneralSecurityException | ScramException | RuntimeException e) {
				result = new SCRAMFailedSASLResult();
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
		private Subject subject;

		public SCRAMSASLResult(String userName, ScramServerFunctionality scram, Subject subject) {
			this.userName = userName;
			this.scram = scram;
			this.subject = subject;
		}

		@Override
		public String getUser() {
			return userName;
		}

		@Override
		public Subject getSubject() {
			return subject;
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
