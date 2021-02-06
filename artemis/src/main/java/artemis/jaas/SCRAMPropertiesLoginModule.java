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
package artemis.jaas;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import javax.crypto.Mac;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;

import org.apache.activemq.artemis.spi.core.security.jaas.AuditLoginModule;
import org.apache.activemq.artemis.spi.core.security.jaas.PropertiesLoader;
import org.apache.activemq.artemis.spi.core.security.jaas.PropertiesLoginModule;
import org.apache.activemq.artemis.spi.core.security.jaas.RolePrincipal;
import org.apache.activemq.artemis.spi.core.security.jaas.UserPrincipal;
import org.apache.activemq.artemis.utils.PasswordMaskingUtil;

import com.bolyartech.scram_sasl.common.ScramException;
import com.bolyartech.scram_sasl.common.ScramUtils;
import com.bolyartech.scram_sasl.server.UserData;

import artemis.SCRAM;

public class SCRAMPropertiesLoginModule extends PropertiesLoader implements AuditLoginModule {

	private static final String SEPARATOR = ":";
	private static final int MIN_ITERATIONS = 4096;
	private Subject subject;
	private CallbackHandler callbackHandler;
	private Properties users;
	private Map<String, Set<String>> roles;
	private UserData userData;
	private String user;
	private final Set<Principal> principals = new HashSet<>();

	@Override
	public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
			Map<String, ?> options) {
		this.subject = subject;
		this.callbackHandler = callbackHandler;

		init(options);
		users = load(PropertiesLoginModule.USER_FILE_PROP_NAME, "user", options).getProps();
		roles = load(PropertiesLoginModule.ROLE_FILE_PROP_NAME, "role", options).invertedPropertiesValuesMap();

	}

	@Override
	public boolean login() throws LoginException {
		NameCallback nameCallback = new NameCallback("Username: ");
		executeCallbacks(new Callback[] { nameCallback });
		user = nameCallback.getName();
		if (user == null) {
			throw new FailedLoginException("User is null");
		}
		String password = users.getProperty(user);
		if (password == null) {
			throw new FailedLoginException("User does not exist: " + user);
		}
		if (PasswordMaskingUtil.isEncMasked(password)) {
			String[] unwrap = PasswordMaskingUtil.unwrap(password).split(SEPARATOR);
			userData = new UserData(unwrap[0], Integer.parseInt(unwrap[1]), unwrap[2], unwrap[3]);
		} else {
			DigestCallback digestCallback = new DigestCallback();
			HmacCallback hmacCallback = new HmacCallback();
			executeCallbacks(new Callback[] { digestCallback, hmacCallback });
			byte[] salt = generateSalt();
			try {
				ScramUtils.NewPasswordStringData data = ScramUtils.byteArrayToStringData(ScramUtils
						.newPassword(password, salt, 4096, digestCallback.getDigest(), hmacCallback.getHmac()));
				userData = new UserData(data.salt, data.iterations, data.serverKey, data.storedKey);
			} catch (ScramException e) {
				throw new LoginException();
			}
		}
		return true;
	}

	private static byte[] generateSalt() {
		byte[] salt = new byte[24];
		SecureRandom random = new SecureRandom();
		random.nextBytes(salt);
		return salt;
	}

	private void executeCallbacks(Callback[] callbacks) throws LoginException {
		try {
			callbackHandler.handle(callbacks);
		} catch (UnsupportedCallbackException | IOException e) {
			throw new LoginException();
		}
	}

	@Override
	public boolean commit() throws LoginException {
		if (userData == null) {
			throw new LoginException();
		}
		subject.getPublicCredentials().add(userData);
		Set<UserPrincipal> authenticatedUsers = subject.getPrincipals(UserPrincipal.class);
		UserPrincipal principal = new UserPrincipal(user);
		principals.add(principal);
		authenticatedUsers.add(principal);
		for (UserPrincipal userPrincipal : authenticatedUsers) {
			Set<String> matchedRoles = roles.get(userPrincipal.getName());
			if (matchedRoles != null) {
				for (String entry : matchedRoles) {
					principals.add(new RolePrincipal(entry));
				}
			}
		}
		subject.getPrincipals().addAll(principals);
		return true;
	}

	@Override
	public boolean abort() throws LoginException {
		return true;
	}

	@Override
	public boolean logout() throws LoginException {
		subject.getPrincipals().removeAll(principals);
		principals.clear();
		subject.getPublicCredentials().remove(userData);
		userData = null;
		return true;
	}

	public static void main(String[] args) throws GeneralSecurityException, ScramException {
		if (args.length < 3) {
			System.out.println("Usage: " + SCRAMPropertiesLoginModule.class.getSimpleName()
					+ " <username> <password> <type> [<iterations>]");
			System.out.println("\ttype: "
					+ getSupportedTypes());
			System.out.println("\titerations desired number of iteration (min value: " + MIN_ITERATIONS + ")");
			return;
		}
		String username = args[0];
		String password = args[1];
		String type = args[2];
		SCRAM scram = Arrays.stream(SCRAM.values()).filter(v -> v.getName().equals(type)).findFirst()
				.orElseThrow(() -> new IllegalArgumentException(
						"unkown type " + type + ", supported ones are " + getSupportedTypes()));
		MessageDigest digest = MessageDigest.getInstance(scram.getDigest());
		Mac hmac = Mac.getInstance(scram.getHmac());
		byte[] salt = generateSalt();
		int iterations;
		if (args.length > 3) {
			iterations = Integer.parseInt(args[3]);
			if (iterations < MIN_ITERATIONS) {
				throw new IllegalArgumentException("minimum of " + MIN_ITERATIONS + " required!");
			}
		} else {
			iterations = MIN_ITERATIONS;
		}
		ScramUtils.NewPasswordStringData data = ScramUtils
				.byteArrayToStringData(ScramUtils.newPassword(password, salt, iterations, digest, hmac));
		System.out.println(username + " = "
				+ PasswordMaskingUtil
						.wrap(data.salt + SEPARATOR + data.iterations + SEPARATOR + data.serverKey + SEPARATOR
								+ data.storedKey));
	}

	private static String getSupportedTypes() {
		return String.join(", ", Arrays.stream(SCRAM.values()).map(SCRAM::getName).toArray(String[]::new));
	}

}
