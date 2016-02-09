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
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;

import de.petendi.commons.crypto.model.HybridEncrypted;

public class HybridCrypto {

    private byte[] symmetricPassPhrase = null;
    private HybridEncrypted encryptedMessage = new HybridEncrypted();
    private SymmetricCrypto symmetricCrypto = new SymmetricCrypto();
    private AsymmetricCrypto asymmetricCrypto;
    private final SecurityProviderConnector securityProviderConnector;
    public HybridCrypto(SecurityProviderConnector securityProviderConnector) {
        this.securityProviderConnector = securityProviderConnector;
        asymmetricCrypto = new AsymmetricCrypto(securityProviderConnector);
        encryptedMessage.setHeaders(new HashMap<String, String>());
        encryptedMessage.setRecipients(new HashMap<String, byte[]>());
        encryptedMessage.setCertificates(new HashMap<String, String>());
    }

    private synchronized void createSymmetricPassphrase() {
        if (symmetricPassPhrase == null) {
            symmetricPassPhrase = securityProviderConnector.generateSecretKey().getEncoded();
        }
    }

    public HybridCrypto addRecipient(String recipientIdentifier, Reader pemReader) {
        try {
            createSymmetricPassphrase();
            String certificate = IOUtils.toString(pemReader);
            byte[] encryptedPassPhrase = asymmetricCrypto.encrypt(symmetricPassPhrase, new StringReader(certificate));
            encryptedMessage.getRecipients().put(recipientIdentifier, encryptedPassPhrase);
            encryptedMessage.getCertificates().put(recipientIdentifier,certificate);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    public HybridCrypto addRecipient(String recipientIdentifier, X509Certificate certificate) {
        try {
            createSymmetricPassphrase();
            byte[] encryptedPassPhrase = asymmetricCrypto.encrypt(symmetricPassPhrase, certificate.getPublicKey());
            encryptedMessage.getRecipients().put(recipientIdentifier, encryptedPassPhrase);
            StringWriter pemWriter = new StringWriter();
            securityProviderConnector.writeCertificate(pemWriter, certificate);
            encryptedMessage.getCertificates().put(recipientIdentifier, pemWriter.toString());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    public HybridEncrypted build(byte[] message,char[] signPassword,InputStream pkcs12Stream) {
        byte[] encryptedBody = encryptInternal(message);
        Signature signature = new Signature(securityProviderConnector);
        byte[] signed = signature.sign(encryptedBody,signPassword,pkcs12Stream);
        encryptedMessage.setSignature(signed);
        return encryptedMessage;
    }

    public HybridEncrypted build(byte[] message,PrivateKey privateKey) {
        byte[] encryptedBody = encryptInternal(message);
        Signature signature = new Signature(securityProviderConnector);
        byte[] signed = signature.sign(encryptedBody,privateKey);
        encryptedMessage.setSignature(signed);
        return encryptedMessage;
    }

    private byte[] encryptInternal(byte[] message) {
        createSymmetricPassphrase();
        char[] base64PassPhrase = Base64.getEncoder().encodeToString(symmetricPassPhrase).toCharArray();
        byte[] encryptedBody = symmetricCrypto.encrypt(message, base64PassPhrase);
        encryptedMessage.setEncryptedBody(encryptedBody);
        return encryptedBody;
    }

    public byte[] decrypt(HybridEncrypted encrypted,String recipientIdentifier,char[] password,InputStream pkcs12Stream) {
        byte[] encryptedPassphrase = encrypted.getRecipients()
                .get(recipientIdentifier);
        char[] chars = retrievePassPhrase(encryptedPassphrase, password, pkcs12Stream);
        return symmetricCrypto.decrypt(encrypted
                .getEncryptedBody(), chars);
    }

    public byte[] decrypt(HybridEncrypted encrypted,String recipientIdentifier,PrivateKey privateKey) {
        byte[] encryptedPassphrase = encrypted.getRecipients()
                .get(recipientIdentifier);
        char[] chars = retrievePassPhrase(encryptedPassphrase, privateKey);
        return symmetricCrypto.decrypt(encrypted
                .getEncryptedBody(), chars);
    }

    private char[] retrievePassPhrase(byte[] encryptedPassphrase, PrivateKey privateKey) {
        byte[] passPhrase = asymmetricCrypto.decrypt(
                encryptedPassphrase, privateKey);
        byte[] base64Passphrase = Base64.getEncoder().encode(passPhrase);
        return new String(base64Passphrase).toCharArray();
    }

    private char[] retrievePassPhrase(byte[] encryptedPassphrase, char[] password, InputStream pkcs12Stream) {
        byte[] passPhrase = asymmetricCrypto.decrypt(
                encryptedPassphrase, password,
                pkcs12Stream);
        byte[] base64Passphrase = Base64.getEncoder().encode(passPhrase);
        return new String(base64Passphrase).toCharArray();
    }


}
