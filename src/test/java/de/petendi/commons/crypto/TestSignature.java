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

import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class TestSignature {

    @Test
    public void test() {
        Certificates certificates = new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        String id = "test";
        char[] password = "123".toCharArray();
        certificates.create(id, password, stringWriter,
                byteArrayOutputStream);
        String cert = stringWriter.toString();
        StringReader stringReader = new StringReader(cert);
        Signature signature = new Signature(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        String input = "I want to be signed!";
        byte[] signed = signature.sign(input.getBytes(), password, new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
        Signature freshSignature = new Signature(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        Assert.assertTrue(freshSignature.verify(input.getBytes(), signed, stringReader));
    }

    @Test
    public void testWithOtherKey() {
        String privateKey = "my-privatekey";
        Certificates certificates = new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector(),"my-issuer", privateKey, null);
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        String id = "test";
        char[] password = "123".toCharArray();
        certificates.create(id, password, stringWriter,
                byteArrayOutputStream);
        String cert = stringWriter.toString();
        StringReader stringReader = new StringReader(cert);
        Signature signature = new Signature(SecurityProviderConnectorFactory.getSecurityProviderConnector(),privateKey);
        String input = "I want to be signed!";
        byte[] signed = signature.sign(input.getBytes(), password, new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
        Signature freshSignature = new Signature(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        Assert.assertTrue(freshSignature.verify(input.getBytes(), signed, stringReader));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testInvalid() {
        Certificates certificates = new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        String id = "test";
        char[] password = "123".toCharArray();
        certificates.create(id, password, stringWriter,
                byteArrayOutputStream);
        Signature signature = new Signature(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        signature.sign(null, null, new ByteArrayInputStream(byteArrayOutputStream.toByteArray()));
    }

    @Test
    public void testWithPublicAndPrivateDirectly() throws Exception {
        Certificates certificates = new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        String id = "test";
        char[] password = "123".toCharArray();
       X509Certificate cert =  certificates.create(id, password, stringWriter,
                byteArrayOutputStream);
        Signature signature = new Signature(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        String input = "I want to be signed!";
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
        byte[] signed = signature.sign(input.getBytes(), new PrivateKeyExtractor().extract(password, byteArrayInputStream));
        Signature freshSignature = new Signature(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        Assert.assertTrue(freshSignature.verify(input.getBytes(), signed, cert.getPublicKey()));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testSignError() {
        Signature signature = new Signature(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        signature.sign(new byte[]{0, 1}, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testVerifyError() {
        Signature signature = new Signature(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        signature.verify(new byte[]{0, 1}, new byte[]{0, 1}, (PublicKey) null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testVerifyErrorReader() {
        Signature signature = new Signature(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        signature.verify(new byte[]{0, 1},new byte[]{0, 1}, (Reader)null);
    }


}
