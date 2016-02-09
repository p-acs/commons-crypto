/**
 * Copyright 2015  Jan Petendi <jan.petendi@p-acs.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.petendi.commons.crypto;

import de.petendi.commons.crypto.connector.SecurityProviderConnector;

import java.util.Arrays;

public class Hash {
    private final SecurityProviderConnector securityProviderConnector;

    public Hash(SecurityProviderConnector securityProviderConnector) {
        this.securityProviderConnector = securityProviderConnector;
    }

    public byte[] hash(byte[] input) {
        return securityProviderConnector.hash(input);
    }

    public boolean isValid(byte[] input,byte[] hashedInput) {
        return Arrays.equals(hash(input),hashedInput);
    }


}
