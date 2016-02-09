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

import org.cryptonode.jncryptor.CryptorException;
import org.cryptonode.jncryptor.JNCryptor;
import org.junit.Assert;
import org.junit.Test;

import static org.mockito.Mockito.*;

public class TestSymmetricCrypto {
    
    private static class MockSymmetricCrypto extends SymmetricCrypto {
        public MockSymmetricCrypto(JNCryptor cryptor) {
            super(cryptor);
        }
    }
    private  byte[] plain = "secret".getBytes();
    private char[] passPhrase = "1234567890".toCharArray();

    @Test
    public void test() {
       
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto();
        byte[] encrypted = symmetricCrypto.encrypt(plain, passPhrase);
        byte[] decrypted = symmetricCrypto.decrypt(encrypted, passPhrase);
        Assert.assertArrayEquals(plain, decrypted);
    }
    
    @Test(expected=IllegalStateException.class)
    public void testWrongPassPhrase() {
       
        SymmetricCrypto symmetricCrypto = new SymmetricCrypto();
        byte[] encrypted = symmetricCrypto.encrypt(plain, passPhrase);
        symmetricCrypto.decrypt(encrypted, "0987654321".toCharArray());
    }
    
  
    @Test(expected=IllegalStateException.class)
    public void testCryptorExceptionEncrypt() throws CryptorException {
        JNCryptor mockCryptor = mock(JNCryptor.class);
        when(mockCryptor.encryptData(plain, passPhrase)).thenThrow(new CryptorException());
        MockSymmetricCrypto mockSymmetricCrypto = new MockSymmetricCrypto(mockCryptor);
        mockSymmetricCrypto.encrypt(plain, passPhrase);
    }
    
    
    @Test(expected=IllegalStateException.class)
    public void testCryptorExceptionDecrypt() throws CryptorException {
        JNCryptor mockCryptor = mock(JNCryptor.class);
        when(mockCryptor.decryptData(plain, passPhrase)).thenThrow(new CryptorException());
        MockSymmetricCrypto mockSymmetricCrypto = new MockSymmetricCrypto(mockCryptor);
        mockSymmetricCrypto.decrypt(plain, passPhrase);
    }
    
    
    
    
}
