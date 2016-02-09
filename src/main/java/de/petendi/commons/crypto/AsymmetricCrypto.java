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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.InputStream;
import java.io.Reader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class AsymmetricCrypto extends BaseAsymmetric {



    public AsymmetricCrypto(SecurityProviderConnector securityProviderConnector) {
        super(securityProviderConnector);
    }

    public AsymmetricCrypto(SecurityProviderConnector securityProviderConnector, String privateKeyEntry) {
        super(securityProviderConnector,privateKeyEntry);
    }

    public byte[] decrypt(byte[] encrypted, char[] password, InputStream pkcs12Stream) {
        try {
            PrivateKey privateKey = extractPrivateKey(password, pkcs12Stream);
            return decryptInternal(encrypted, privateKey);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public byte[] decrypt(byte[] encrypted, PrivateKey privateKey) {
        try {
            return decryptInternal(encrypted,privateKey);
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException | InvalidKeyException
                | IllegalBlockSizeException | BadPaddingException  | NoSuchProviderException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private byte[] decryptInternal(byte[] encrypted, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher rsa = Cipher.getInstance(securityProviderConnector.getCryptoAlgorithm(), securityProviderConnector.getProviderName());
        rsa.init(Cipher.DECRYPT_MODE, privateKey);
        return rsa.doFinal(encrypted);
    }

    public byte[] encrypt(byte[] plain, PublicKey publicKey) {
        try {
            return encryptInternal(plain, publicKey);
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException | InvalidKeyException
                | IllegalBlockSizeException | BadPaddingException  | NoSuchProviderException e) {
            throw new IllegalArgumentException(e);
        }
    }


    public byte[] encrypt(byte[] plain, Reader pemReader) {
        try {
            PublicKey publicKey = extractPublicKey(pemReader);
            return encryptInternal(plain, publicKey);
        } catch (CryptoException | NoSuchAlgorithmException
                | NoSuchPaddingException | InvalidKeyException
                | IllegalBlockSizeException | BadPaddingException  | NoSuchProviderException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private byte[] encryptInternal(byte[] plain, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher rsa = Cipher.getInstance(securityProviderConnector.getCryptoAlgorithm(),  securityProviderConnector.getProviderName());
        rsa.init(Cipher.ENCRYPT_MODE, publicKey);
        return rsa.doFinal(plain);
    }
}
