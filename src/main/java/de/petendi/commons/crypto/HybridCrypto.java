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
import de.petendi.commons.crypto.model.HybridEncrypted;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

import org.apache.commons.io.IOUtils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class HybridCrypto {

    private final String SYMMETRIC_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";

    private byte[] iv = null;
    private SecretKey symmetricKey = null;
    private byte[] concatenated = null;
    private HybridEncrypted encryptedMessage = new HybridEncrypted();
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
        if (symmetricKey == null) {
            symmetricKey = securityProviderConnector.generateSecretKey();
            SecureRandom randomSecureRandom = new SecureRandom();
            iv = new byte[16];
            randomSecureRandom.nextBytes(iv);
            byte[] encodedKey = symmetricKey.getEncoded();
            concatenated = new byte[iv.length + encodedKey.length];
            System.arraycopy(iv, 0, concatenated, 0, iv.length);
            System.arraycopy(encodedKey, 0, concatenated, iv.length, encodedKey.length);
        }
    }

    public HybridCrypto addRecipient(String recipientIdentifier, Reader pemReader) {
        try {
            createSymmetricPassphrase();
            String certificate = IOUtils.toString(pemReader);
            byte[] encryptedPassPhrase = asymmetricCrypto.encrypt(concatenated, new StringReader(certificate));
            encryptedMessage.getRecipients().put(recipientIdentifier, encryptedPassPhrase);
            encryptedMessage.getCertificates().put(recipientIdentifier, certificate);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    public HybridCrypto addRecipient(String recipientIdentifier, X509Certificate certificate) {
        try {
            createSymmetricPassphrase();
            byte[] encryptedPassPhrase = asymmetricCrypto.encrypt(concatenated, certificate.getPublicKey());
            encryptedMessage.getRecipients().put(recipientIdentifier, encryptedPassPhrase);
            StringWriter pemWriter = new StringWriter();
            securityProviderConnector.writeCertificate(pemWriter, certificate);
            encryptedMessage.getCertificates().put(recipientIdentifier, pemWriter.toString());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return this;
    }

    public HybridEncrypted build(byte[] message, char[] signPassword, InputStream pkcs12Stream) {
        byte[] encryptedBody = encryptInternal(message);
        Signature signature = new Signature(securityProviderConnector);
        byte[] signed = signature.sign(encryptedBody, signPassword, pkcs12Stream);
        encryptedMessage.setSignature(signed);
        return encryptedMessage;
    }

    public HybridEncrypted build(byte[] message, PrivateKey privateKey) {
        byte[] encryptedBody = encryptInternal(message);
        Signature signature = new Signature(securityProviderConnector);
        byte[] signed = signature.sign(encryptedBody, privateKey);
        encryptedMessage.setSignature(signed);
        return encryptedMessage;
    }

    private byte[] encryptInternal(byte[] message) {
        createSymmetricPassphrase();

        try {
            Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, new IvParameterSpec(iv));
            byte[] encryptedBody = cipher.doFinal(message);
            encryptedMessage.setEncryptedBody(encryptedBody);
            return encryptedBody;
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public byte[] decrypt(HybridEncrypted encrypted, String recipientIdentifier, char[] password, InputStream pkcs12Stream) {
        byte[] encryptedPassphrase = encrypted.getRecipients()
                .get(recipientIdentifier);
        try {
            ArrayList<byte[]> splitted = retrieveSecretAndIV(encryptedPassphrase, password, pkcs12Stream);
            Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER_ALGORITHM);
            SecretKey originalKey = new SecretKeySpec(splitted.get(1), 0, splitted.get(1).length, "AES");
            cipher.init(Cipher.DECRYPT_MODE, originalKey, new IvParameterSpec(splitted.get(0)));
            return cipher.doFinal(encrypted.getEncryptedBody());
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public byte[] decrypt(HybridEncrypted encrypted, String recipientIdentifier, PrivateKey privateKey) {
        byte[] encryptedPassphrase = encrypted.getRecipients()
                .get(recipientIdentifier);
        try {
            ArrayList<byte[]> splitted = retrieveSecretAndIV(encryptedPassphrase, privateKey);
            Cipher cipher = Cipher.getInstance(SYMMETRIC_CIPHER_ALGORITHM);
            SecretKey originalKey = new SecretKeySpec(splitted.get(1), 0, splitted.get(1).length, "AES");
            cipher.init(Cipher.DECRYPT_MODE, originalKey, new IvParameterSpec(splitted.get(0)));
            return cipher.doFinal(encrypted.getEncryptedBody());
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }


    private ArrayList<byte[]> retrieveSecretAndIV(byte[] encryptedPassphrase, PrivateKey privateKey) {
        byte[] concatenated = asymmetricCrypto.decrypt(
                encryptedPassphrase, privateKey);
        ArrayList<byte[]> splitted = splitSecretAndIV(concatenated);
        return splitted;
    }

    private ArrayList<byte[]> retrieveSecretAndIV(byte[] encryptedPassphrase, char[] password, InputStream pkcs12Stream) {
        byte[] concatenated = asymmetricCrypto.decrypt(
                encryptedPassphrase, password,
                pkcs12Stream);
        ArrayList<byte[]> splitted = splitSecretAndIV(concatenated);
        return splitted;
    }

    private ArrayList<byte[]> splitSecretAndIV(byte[] concatenated) {
        byte[] iv = Arrays.copyOfRange(concatenated, 0, 16);
        byte[] symmetricKey = Arrays.copyOfRange(concatenated, 16, concatenated.length);
        ArrayList<byte[]> splitted = new ArrayList<>(2);
        splitted.add(0, iv);
        splitted.add(1, symmetricKey);
        return splitted;
    }


}
