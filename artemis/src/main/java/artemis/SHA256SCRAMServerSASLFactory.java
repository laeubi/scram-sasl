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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import com.bolyartech.scram_sasl.common.ScramUtils;
import com.bolyartech.scram_sasl.server.UserData;

public class SHA256SCRAMServerSASLFactory extends SCRAMServerSASLFactory {

	public SHA256SCRAMServerSASLFactory() {
		super("SCRAM-SHA-256", "SHA-256", "HmacSHA256");
	}

	@Override
	protected UserData getUserData() {
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[24];
		random.nextBytes(salt);
		try {
			ScramUtils.NewPasswordStringData data = ScramUtils
					.byteArrayToStringData(ScramUtils.newPassword("ogre1234", salt, 4096, "SHA-256", "HmacSHA256"));
			return new UserData(data.salt, data.iterations, data.serverKey, data.storedKey);

		} catch (NoSuchAlgorithmException | InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public int getPrecedence() {
		return 200;
	}
}
