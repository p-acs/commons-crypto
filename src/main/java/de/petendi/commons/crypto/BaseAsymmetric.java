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

import de.petendi.commons.crypto.connector.CryptoException;
import de.petendi.commons.crypto.connector.SecurityProviderConnector;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

abstract class BaseAsymmetric {


    protected final String privateKeyEntryString;
    protected final SecurityProviderConnector securityProviderConnector;

    protected BaseAsymmetric(SecurityProviderConnector securityProviderConnector) {
        this(securityProviderConnector,"private-key");
    }

    protected BaseAsymmetric(SecurityProviderConnector securityProviderConnector, String privateKeyEntry) {
        this.privateKeyEntryString = privateKeyEntry;
        this.securityProviderConnector = securityProviderConnector;
    }

    protected final PrivateKey extractPrivateKey(char[] password, InputStream pkcs12Stream) throws NoSuchProviderException, KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, UnrecoverableEntryException {
        KeyStore inStore = KeyStore.getInstance("PKCS12", securityProviderConnector.getProviderName());
        inStore.load(pkcs12Stream,
                password);
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) inStore
                .getEntry(privateKeyEntryString, new KeyStore.PasswordProtection(
                        password));
        return privateKeyEntry.getPrivateKey();
    }

    protected final PublicKey extractPublicKey(Reader pemReader) throws CryptoException {
        return securityProviderConnector.extractPublicKey(pemReader);
    }

    public final boolean containsPrivateKey(char[] password, InputStream pkcs12Stream) {
        try {
            extractPrivateKey(password, pkcs12Stream);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public final boolean containsPublicKey(Reader pemReader) {
        try {
            extractPublicKey(pemReader);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
