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

import org.cryptonode.jncryptor.AES256JNCryptor;
import org.cryptonode.jncryptor.CryptorException;
import org.cryptonode.jncryptor.JNCryptor;


public class SymmetricCrypto {
    private JNCryptor cryptor;
    
    public SymmetricCrypto() {
        this(new AES256JNCryptor());
    }
    
    protected SymmetricCrypto(JNCryptor cryptor) {
        this.cryptor = cryptor;
    }

    public byte[] decrypt(byte[] encrypted, char[] password) {
        byte[] plainText;
        try {
            plainText = cryptor.decryptData(encrypted, password);
        } catch (CryptorException e) {
            throw new IllegalStateException(e);
        }
        return plainText;

    }

    public byte[] encrypt(byte[] plaintext, char[] password) {
        byte[] ciphertext;
        try {
            ciphertext = cryptor.encryptData(plaintext, password);
        } catch (CryptorException e) {
            throw new IllegalStateException(e);
        }
        return ciphertext;
    }

}
