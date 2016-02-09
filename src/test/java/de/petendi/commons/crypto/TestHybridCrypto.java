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

import de.petendi.commons.crypto.model.HybridEncrypted;

public class TestHybridCrypto {

    @Test
    public void test() {
        HybridCrypto hybridCrypto = new HybridCrypto(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        Certificates certificates = new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        String id = "test";
        char[] password = "123".toCharArray();
        certificates.create(id, password, stringWriter,
                byteArrayOutputStream);
        String cert = stringWriter.toString();
        StringReader stringReader = new StringReader(cert);
        hybridCrypto.addRecipient("test", stringReader);
        String message = "I am hybrid encrypted!";
        HybridEncrypted hybridEncrypted = hybridCrypto.build(message.getBytes(),password,new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
        HybridCrypto freshHybridCrypto = new HybridCrypto(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        byte[] decryptedMessage = freshHybridCrypto.decrypt(hybridEncrypted,id,password,new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
        Assert.assertArrayEquals(message.getBytes(),decryptedMessage);
        Signature signature = new Signature(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        Assert.assertTrue(signature.verify(hybridEncrypted.getEncryptedBody(),hybridEncrypted.getSignature(),new StringReader(cert)));
    }


    @Test
    public void testPublicPrivate() throws Exception {
        HybridCrypto hybridCrypto = new HybridCrypto(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        Certificates certificates = new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        String id = "test";
        char[] password = "123".toCharArray();
        X509Certificate cert = certificates.create(id, password, stringWriter,
                byteArrayOutputStream);
        hybridCrypto.addRecipient("test", cert);
        String message = "I am hybrid encrypted!";
        HybridEncrypted hybridEncrypted = hybridCrypto.build(message.getBytes(), new PrivateKeyExtractor().extractPrivateKey(password,new ByteArrayInputStream(byteArrayOutputStream.toByteArray())));
        HybridCrypto freshHybridCrypto = new HybridCrypto(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        byte[] decryptedMessage = freshHybridCrypto.decrypt(hybridEncrypted,id,new PrivateKeyExtractor().extractPrivateKey(password,new ByteArrayInputStream(byteArrayOutputStream.toByteArray())));
        Assert.assertArrayEquals(message.getBytes(),decryptedMessage);
        Signature signature = new Signature(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        Assert.assertTrue(signature.verify(hybridEncrypted.getEncryptedBody(),hybridEncrypted.getSignature(),cert.getPublicKey()));
    }
}
