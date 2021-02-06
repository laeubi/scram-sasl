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

import javax.crypto.Mac;
import javax.security.auth.callback.Callback;

public class HmacCallback implements Callback {

	private Mac hmac;

	public void setHmac(Mac hmac) {
		this.hmac = hmac;
	}

	public Mac getHmac() {
		return hmac;
	}

}