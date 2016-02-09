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
import java.io.StringReader;
import java.io.StringWriter;

public class TestBaseCrypto {

    @Test
    public void testContainsPublicOK() {
        Certificates certificates = new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        String id = "test";
        char[] password = "123".toCharArray();
        certificates.create(id, password, stringWriter,
                byteArrayOutputStream);
        String cert = stringWriter.toString();
        StringReader stringReader = new StringReader(cert);
        MockBaseCrypto baseCrypto = new MockBaseCrypto();
        Assert.assertTrue(baseCrypto.containsPublicKey(stringReader));
    }

    @Test
    public void testContainsPublicFailure() {
        String cert =  "blabla";
        StringReader stringReader = new StringReader(cert);
        MockBaseCrypto baseCrypto = new MockBaseCrypto();
        Assert.assertFalse(baseCrypto.containsPublicKey(stringReader));
    }

    @Test
    public void testContainsPrivateOK() {
        Certificates certificates = new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        String id = "test";
        char[] password = "123".toCharArray();
        certificates.create(id, password, stringWriter,
                byteArrayOutputStream);
        MockBaseCrypto baseCrypto = new MockBaseCrypto();
        Assert.assertTrue(baseCrypto.containsPrivateKey(password, new ByteArrayInputStream(byteArrayOutputStream.toByteArray())));

    }

    @Test
    public void testContainsPrivateFailure() {
        MockBaseCrypto baseCrypto = new MockBaseCrypto();
        Assert.assertFalse(baseCrypto.containsPrivateKey("pw".toCharArray(), new ByteArrayInputStream("wrong".getBytes())));
    }

    private static class MockBaseCrypto extends BaseAsymmetric {
        MockBaseCrypto() {
            super(SecurityProviderConnectorFactory.getSecurityProviderConnector());
        }

    }
}
