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

import java.io.OutputStream;
import java.io.Writer;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;


public final class Certificates {

    private String issuer;
    private String privateKeyEntry;
    private String crlUri;
    private final SecurityProviderConnector securityProviderConnector;

    public Certificates(SecurityProviderConnector securityProviderConnector) {
        this(securityProviderConnector,"issuer");
    }

    public Certificates(SecurityProviderConnector securityProviderConnector,String issuer) {
        this(securityProviderConnector,issuer,"private-key",null);
    }

    public Certificates(SecurityProviderConnector securityProviderConnector, String issuer, String privateKeyEntry, String crlUri) {
        this.securityProviderConnector = securityProviderConnector;
        this.issuer = issuer;
        this.privateKeyEntry = privateKeyEntry;
        this.crlUri = crlUri;
    }


    public X509Certificate create(String userId,KeyStore keyStore) {
        if(keyStore==null) {
            throw new IllegalArgumentException("no keyStore given");
        }
        return create(userId,null,keyStore,null);
    }

    private X509Certificate create(String userId,Writer pemWriter,KeyStore keyStore,char[] password) {
        return create(userId,password,pemWriter,null,keyStore);
    }

    public X509Certificate create(String userId,
                                  char[] password, Writer pemWriter, OutputStream pkcs12Output) {
        if(pkcs12Output==null) {
            throw new IllegalArgumentException("no stream for pkcs12 given");
        }
        return create(userId,password,pemWriter,pkcs12Output,null);
    }

    private  X509Certificate createCertificate(String dn, String issuer,String crlUri,
                                               PublicKey publicKey, PrivateKey privateKey)  {
        try {
            return securityProviderConnector.createCertificate(dn, issuer, crlUri, publicKey, privateKey);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private X509Certificate create(String userId,
            char[] password, Writer pemWriter, OutputStream pkcs12Output,final KeyStore keyStore) {

        if (userId == null) {
            throw new IllegalArgumentException("userId must not be null");
        }

        X509Certificate selfCert;
        try {

            java.security.KeyPair keyPair = securityProviderConnector.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            selfCert = createCertificate("CN=" + userId, "CN=" + issuer,crlUri,
                    publicKey, privateKey);
            java.security.cert.Certificate[] outChain = { selfCert };
            if(pemWriter!=null) {
                securityProviderConnector.writeCertificate(pemWriter, selfCert);
            }
            KeyStore keyStoreToUse;
            if(keyStore == null) {
                keyStoreToUse = KeyStore.getInstance("PKCS12", securityProviderConnector.getProviderName());
                keyStoreToUse.load(null, password);
            } else {
                keyStoreToUse = keyStore;
            }

            keyStoreToUse.setKeyEntry(privateKeyEntry, privateKey,
                    password, outChain);
            if(pkcs12Output!=null) {
                keyStoreToUse.store(pkcs12Output, password);
                pkcs12Output.flush();
                pkcs12Output.close();
            }

        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return selfCert;
    }




}
