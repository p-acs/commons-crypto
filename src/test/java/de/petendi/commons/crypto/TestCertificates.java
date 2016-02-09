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

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import org.junit.Test;

public class TestCertificates {
    
    
    @Test(expected=IllegalArgumentException.class)
    public void testNoUserId() throws Exception {
        new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector()).create(null, "123".toCharArray(), new StringWriter(), new ByteArrayOutputStream());
    }
    
    @Test(expected=IllegalArgumentException.class)
    public void testCrash() throws Exception {
        new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector()).create("user-123", "123".toCharArray(), new StringWriter(), null);
    }
    
    @Test
    public void testCertOk() throws Exception {
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector()).create("user-123", "123".toCharArray(), stringWriter, byteArrayOutputStream);
        String pem = stringWriter.toString();
        assertTrue(pem.contains("-----BEGIN CERTIFICATE-----"));
        assertTrue(pem.contains("-----END CERTIFICATE-----"));
    }

    @Test
    public void testCrlNotNull() throws Exception {
        StringWriter stringWriter = new StringWriter();
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector(),"myIssuer","myKey","https://crl.p-acs.de").create("user-123", "123".toCharArray(), stringWriter, byteArrayOutputStream);
        String pem = stringWriter.toString();
        assertTrue(pem.contains("-----BEGIN CERTIFICATE-----"));
        assertTrue(pem.contains("-----END CERTIFICATE-----"));
    }

    @Test
    public void testCreateWithCustomKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector()).create("user-123", keyStore);
        assertTrue(keyStore.containsAlias("private-key"));
    }

    @Test(expected = IllegalStateException.class)
    public void testCreateWithUnSupportedCustomKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null,null);
        new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector()).create("user-123",keyStore);
        assertTrue(keyStore.containsAlias("private-key"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testCreateWithNullKeyStore() throws Exception {
        new Certificates(SecurityProviderConnectorFactory.getSecurityProviderConnector()).create("user-123", null);
    }
    
}
