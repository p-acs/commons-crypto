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
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.cert.X509Certificate;

public class TestReadMe {

    private StringReader carolsPemReader = null;
    private byte[] carolsPkcs12 = null;


    @Before
    public void setup() {
        SecurityProviderConnector connector = SecurityProviderConnectorFactory.getSecurityProviderConnector();
        StringWriter carolPemWriter = new StringWriter();
        ByteArrayOutputStream carolsPkcs12Stream = new ByteArrayOutputStream();
        X509Certificate carolsCertificate = new Certificates(connector,"Your Product").create("carol","carols_password".toCharArray() ,
                carolPemWriter,carolsPkcs12Stream);
        carolsPemReader = new StringReader(carolPemWriter.toString());
        carolsPkcs12 = carolsPkcs12Stream.toByteArray();

        Assert.assertTrue(carolsCertificate.getIssuerDN().getName().contains("Your Product"));
        Assert.assertTrue(carolsCertificate.getSubjectDN().getName().contains("carol"));

    }

    @Test
    public void test() {
        SecurityProviderConnector connector = SecurityProviderConnectorFactory.getSecurityProviderConnector();

        StringWriter alicesPemWriter = new StringWriter();
        ByteArrayOutputStream alicesPkcs12Stream = new ByteArrayOutputStream();
        char[] alicesPassword = "alices_password".toCharArray();
        X509Certificate alicesCertificate = new Certificates(connector,"Your Product").create("alice",alicesPassword,
                alicesPemWriter, alicesPkcs12Stream);
        String alicesPem = alicesPemWriter.toString();
        byte[] alicesPkcs12 = alicesPkcs12Stream.toByteArray();

        Assert.assertTrue(alicesCertificate.getIssuerDN().getName().contains("Your Product"));
        Assert.assertTrue(alicesCertificate.getSubjectDN().getName().contains("alice"));

        StringWriter bobsPemWriter = new StringWriter();
        ByteArrayOutputStream bobsPkcs12Stream = new ByteArrayOutputStream();
        char[] bobsPassword = "bobs_password".toCharArray();
        X509Certificate bobsCertificate = new Certificates(connector,"Your Product").create("bob",bobsPassword,
                bobsPemWriter, bobsPkcs12Stream);
        String bobsPem = bobsPemWriter.toString();
        byte[] bobsPkcs12 = bobsPkcs12Stream.toByteArray();

        Assert.assertTrue(bobsCertificate.getIssuerDN().getName().contains("Your Product"));
        Assert.assertTrue(bobsCertificate.getSubjectDN().getName().contains("bob"));

        ByteArrayInputStream bobsPkcs12InputStream = new ByteArrayInputStream(bobsPkcs12);
        byte[] plainMessageFromAlice = "How are you? Alice".getBytes();
        AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto(connector);
        byte[] encryptedForBob = asymmetricCrypto.encrypt(plainMessageFromAlice, new StringReader(bobsPem));
        byte[] decryptedFromBob = asymmetricCrypto.decrypt(encryptedForBob, bobsPassword, bobsPkcs12InputStream);

        Assert.assertArrayEquals(plainMessageFromAlice,decryptedFromBob);


        String plainMessageFromBob = "Hi Alice. I'm fine. Up for some pizza tonight at my place together with Carol? Cheers,Bob!";
        StringReader alicesPemReader = new StringReader(alicesPem);
        HybridCrypto hybridCrypto = new HybridCrypto(connector);
        hybridCrypto.addRecipient("alice", alicesPemReader);
        //Carol sent Bob her public key already before writing these lines
        hybridCrypto.addRecipient("carol", carolsPemReader);
        //This message can be decrypted by Alice and Carol
        HybridEncrypted hybridEncrypted = hybridCrypto.build(plainMessageFromBob.getBytes(),bobsPassword,new ByteArrayInputStream(bobsPkcs12));
        byte[] decryptedMessageFromAlice = hybridCrypto.decrypt(hybridEncrypted,"alice",alicesPassword,new ByteArrayInputStream(alicesPkcs12));
        Signature signature = new Signature(connector);
        boolean messageReallySentFromBob = signature.verify(hybridEncrypted.getEncryptedBody(),hybridEncrypted.getSignature(),new StringReader(bobsPem));

        Assert.assertArrayEquals(plainMessageFromBob.getBytes(),decryptedMessageFromAlice);
        Assert.assertTrue(messageReallySentFromBob);

        Assert.assertArrayEquals(plainMessageFromBob.getBytes(),hybridCrypto.decrypt(hybridEncrypted,"carol","carols_password".toCharArray(),
                new ByteArrayInputStream(carolsPkcs12)));

    }
}
