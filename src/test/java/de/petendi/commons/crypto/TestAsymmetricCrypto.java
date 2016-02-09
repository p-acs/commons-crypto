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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;
public class TestAsymmetricCrypto {
    
    @Test
    public void testEncrypt() {
        AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        Certificates certificates = new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        certificates.create("test", "123".toCharArray(), stringWriter, byteArrayOutputStream);
        String cert = stringWriter.toString();
        StringReader stringReader = new StringReader(cert);
        ByteArrayInputStream byteArrayInputStream = 
                new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        byte[] plain = "secret".getBytes();
        byte[] encrypted = asymmetricCrypto.encrypt(plain, stringReader);
        byte[] decrypted = asymmetricCrypto.decrypt(encrypted, "123".toCharArray(), byteArrayInputStream);
        Assert.assertArrayEquals(plain, decrypted);
    }

    @Test
    public void testEncryptPublicPrivate() throws Exception{
        AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        Certificates certificates = new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        X509Certificate cert = certificates.create("test", "123".toCharArray(), stringWriter, byteArrayOutputStream);
        ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        byte[] plain = "secret".getBytes();
        byte[] encrypted = asymmetricCrypto.encrypt(plain, cert.getPublicKey());
        byte[] decrypted = asymmetricCrypto.decrypt(encrypted, new PrivateKeyExtractor().extractPrivateKey("123".toCharArray(), byteArrayInputStream));
        Assert.assertArrayEquals(plain, decrypted);
    }

    @Test
    public void testNullInput() {
        AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        Certificates certificates = new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        certificates.create("test", "123".toCharArray(), stringWriter, byteArrayOutputStream);
        String cert = stringWriter.toString();
        StringReader stringReader = new StringReader(cert);
        ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        byte[] plain = "secret".getBytes();
        byte[] encrypted = asymmetricCrypto.encrypt(plain, stringReader);
        byte[] decrypted = asymmetricCrypto.decrypt(encrypted, "123".toCharArray(), byteArrayInputStream);
        Assert.assertArrayEquals(plain, decrypted);
    }


    @Test
    public void testEncryptCustomKeyEntry() {
        String keyEntry = "keyEntry";
        AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto(SecurityProviderConnectorFactory.getSecurityProviderConnector(),keyEntry);
        Certificates certificates = new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector(),"issuer",keyEntry,null);
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        certificates.create("test", "123".toCharArray(), stringWriter, byteArrayOutputStream);
        String cert = stringWriter.toString();
        StringReader stringReader = new StringReader(cert);
        ByteArrayInputStream byteArrayInputStream =
                new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        byte[] plain = "secret".getBytes();
        byte[] encrypted = asymmetricCrypto.encrypt(plain, stringReader);
        byte[] decrypted = asymmetricCrypto.decrypt(encrypted, "123".toCharArray(), byteArrayInputStream);
        Assert.assertArrayEquals(plain, decrypted);
    }

}
