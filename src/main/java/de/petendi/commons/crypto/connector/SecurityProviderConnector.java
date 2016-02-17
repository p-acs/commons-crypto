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
package de.petendi.commons.crypto.connector;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public interface SecurityProviderConnector {
    X509Certificate createCertificate(String dn, String issuer, String crlUri,
                                      PublicKey publicKey, PrivateKey privateKey) throws CryptoException;
    void writeCertificate(Writer pemWriter, X509Certificate selfCert) throws IOException;
    byte[] hash(byte[] input);
    PublicKey extractPublicKey(Reader pemReader) throws CryptoException;
    String getProviderName();
    String getCryptoAlgorithm();
    String getSignAlgorithm();
    KeyPair generateKeyPair();
    SecretKey generateSecretKey();
    byte[] base64Encode(byte[] toEncode);
    byte[] base64Decode(byte[] toDecode);
}
