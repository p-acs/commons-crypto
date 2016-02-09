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
package de.petendi.commons.crypto.connector;


import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.jcajce.provider.digest.SHA3;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openssl.PEMParser;
import org.spongycastle.openssl.jcajce.JcaPEMWriter;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Calendar;
import java.util.Date;

public class SCConnector implements SecurityProviderConnector {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    public SCConnector() {

    }

    @Override
    public X509Certificate createCertificate(String dn, String issuer, String crlUri,
                                             PublicKey publicKey, PrivateKey privateKey) throws CryptoException {
        Calendar date = Calendar.getInstance();
        // Serial Number
        BigInteger serialNumber = BigInteger
                .valueOf(date.getTimeInMillis());
        // Subject and Issuer DN
        org.bouncycastle.asn1.x500.X500Name subjectDN = new org.bouncycastle.asn1.x500.X500Name(dn);
        org.bouncycastle.asn1.x500.X500Name issuerDN = new org.bouncycastle.asn1.x500.X500Name(issuer);
        // Validity
        Date notBefore = date.getTime();
        date.add(Calendar.YEAR, 20);
        Date notAfter = date.getTime();
        // SubjectPublicKeyInfo
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo subjPubKeyInfo = new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo(
                org.bouncycastle.asn1.ASN1Sequence.getInstance(publicKey.getEncoded()));

        org.bouncycastle.cert.X509v3CertificateBuilder certGen = new org.bouncycastle.cert.X509v3CertificateBuilder(
                issuerDN, serialNumber, notBefore, notAfter, subjectDN,
                subjPubKeyInfo);
        org.bouncycastle.operator.DigestCalculator digCalc = null;
        try {
            digCalc = new org.bouncycastle.operator.bc.BcDigestCalculatorProvider()
                    .get(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(org.bouncycastle.asn1.oiw.OIWObjectIdentifiers.idSHA1));
            org.bouncycastle.cert.X509ExtensionUtils x509ExtensionUtils = new org.bouncycastle.cert.X509ExtensionUtils(digCalc);
            // Subject Key Identifier
            certGen.addExtension(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier, false,
                    x509ExtensionUtils.createSubjectKeyIdentifier(subjPubKeyInfo));
            // Authority Key Identifier
            certGen.addExtension(org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier, false,
                    x509ExtensionUtils.createAuthorityKeyIdentifier(subjPubKeyInfo));
            // Key Usage
            certGen.addExtension(org.bouncycastle.asn1.x509.Extension.keyUsage, false, new org.bouncycastle.asn1.x509.KeyUsage(
                    org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment));
            if (crlUri != null) {
                // CRL Distribution Points
                org.bouncycastle.asn1.x509.DistributionPointName distPointOne = new org.bouncycastle.asn1.x509.DistributionPointName(
                        new org.bouncycastle.asn1.x509.GeneralNames(new org.bouncycastle.asn1.x509.GeneralName(
                                org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier,
                                crlUri)));

                org.bouncycastle.asn1.x509.DistributionPoint[] distPoints = new org.bouncycastle.asn1.x509.DistributionPoint[1];
                distPoints[0] = new org.bouncycastle.asn1.x509.DistributionPoint(distPointOne, null, null);
                certGen.addExtension(org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints, false,
                        new org.bouncycastle.asn1.x509.CRLDistPoint(distPoints));
            }

            // Content Signer
            org.bouncycastle.operator.ContentSigner sigGen = new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder(
                    getSignAlgorithm()).setProvider(getProviderName()).build(privateKey);
            // Certificate
            return new org.bouncycastle.cert.jcajce.JcaX509CertificateConverter()
                    .setProvider(getProviderName()).getCertificate(certGen.build(sigGen));
        } catch (Exception e) {
            throw new CryptoException(e);
        }

    }

    public void writeCertificate(Writer pemWriter, X509Certificate selfCert) throws IOException {
        JcaPEMWriter certWriter = new JcaPEMWriter(pemWriter);
        certWriter.writeObject(selfCert);
        certWriter.flush();
        certWriter.close();
    }

    public byte[] hash(byte[] input) {
        SHA3.DigestSHA3 md = new SHA3.DigestSHA3(512);
        md.update(input);
        return md.digest();
    }

    public final PublicKey extractPublicKey(Reader pemReader) throws CryptoException {
        PEMParser parser = new PEMParser(pemReader);
        Object object;
        try {
            object = parser.readObject();
            pemReader.close();
            parser.close();
            if (object instanceof X509CertificateHolder) {
                X509CertificateHolder x509Holder = (X509CertificateHolder) object;
                X509Certificate x509 = new JcaX509CertificateConverter().setProvider(getProviderName())
                        .getCertificate(x509Holder);
                return x509.getPublicKey();
            } else {
                throw new IllegalArgumentException("no certificate found in pem");
            }
        } catch (IOException e) {
            throw new CryptoException(e);
        } catch (CertificateException e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public String getProviderName() {
        return "SC";
    }

    @Override
    public String getCryptoAlgorithm() {
        return "ECIESwithAES/DHAES/PKCS7Padding";
    }

    @Override
    public String getSignAlgorithm() {
        return "SHA1WITHCVC-ECDSA";
    }

    @Override
    public KeyPair generateKeyPair() {

        try {
            ECGenParameterSpec ecParamSpec = new ECGenParameterSpec("brainpoolp512t1");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", getProviderName());
            keyPairGenerator.initialize(ecParamSpec, new SecureRandom());
            java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return keyPair;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }


    }

    @Override
    public SecretKey generateSecretKey() {
        final int outputKeyLength = 256;
        SecureRandom secureRandom = new SecureRandom();
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        keyGenerator.init(outputKeyLength, secureRandom);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }


}
