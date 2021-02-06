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
import java.security.Principal;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

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

public class SCRAMPropertiesLoginModule extends PropertiesLoader implements AuditLoginModule {

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
			String unwrap = PasswordMaskingUtil.unwrap(password);
			// TODO
		} else {
			DigestCallback digestCallback = new DigestCallback();
			HmacCallback hmacCallback = new HmacCallback();
			executeCallbacks(new Callback[] { digestCallback, hmacCallback });
			SecureRandom random = new SecureRandom();
			byte[] salt = new byte[24];
			random.nextBytes(salt);
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

}
