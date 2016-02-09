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

import java.io.InputStream;
import java.io.Reader;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

public class Signature extends BaseAsymmetric {
    public Signature(SecurityProviderConnector securityProviderConnector) {
        super(securityProviderConnector);
    }

    public Signature(SecurityProviderConnector securityProviderConnector, String privateKeyEntry) {
        super(securityProviderConnector,privateKeyEntry);
    }

    public byte[] sign(byte[] input, char[] password,InputStream pkcs12Stream) {
        try {
            PrivateKey privateKey = extractPrivateKey(password,pkcs12Stream);
            return signInternal(input, privateKey);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public byte[] sign(byte[] input, PrivateKey privateKey) {
        try {
            return signInternal(input, privateKey);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    private byte[] signInternal(byte[] input, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        java.security.Signature signature = java.security.Signature.getInstance(securityProviderConnector.getSignAlgorithm(), securityProviderConnector.getProviderName());
        signature.initSign(privateKey);
        signature.update(input);
        return signature.sign();
    }

    public boolean verify(byte[] input,byte[] signature,PublicKey publicKey) {
        try {
            return verifyInternal(input, signature, publicKey);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }


    public boolean verify(byte[] input,byte[] signature,Reader pemReader) {
        try {
            PublicKey publicKey = extractPublicKey(pemReader);
            return verifyInternal(input, signature, publicKey);
        } catch (Exception e) {
           throw new IllegalArgumentException(e);
        }

    }

    private boolean verifyInternal(byte[] input, byte[] signature, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        java.security.Signature mySignature = java.security.Signature.getInstance(securityProviderConnector.getSignAlgorithm(), securityProviderConnector.getProviderName());
        mySignature.initVerify(publicKey);
        mySignature.update(input);
        return mySignature.verify(signature);
    }

}
