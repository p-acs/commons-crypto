/**
 * Copyright 2015  Jan Petendi <jan.petendi@p-acs.com>
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.petendi.commons.crypto.connector;


import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class BCConnector implements SecurityProviderConnector {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    public BCConnector() {
    }

    @Override
    public X509Certificate createCertificate(String dn, String issuer, String crlUri,
                                             PublicKey publicKey, PrivateKey privateKey) throws CryptoException {
        Calendar date = Calendar.getInstance();
        // Serial Number
        BigInteger serialNumber = BigInteger
                .valueOf(date.getTimeInMillis());
        // Subject and Issuer DN
        X500Name subjectDN = new X500Name(dn);
        X500Name issuerDN = new X500Name(issuer);
        // Validity
        Date notBefore = date.getTime();
        date.add(Calendar.YEAR, 20);
        Date notAfter = date.getTime();
        // SubjectPublicKeyInfo
        SubjectPublicKeyInfo subjPubKeyInfo = new SubjectPublicKeyInfo(
                ASN1Sequence.getInstance(publicKey.getEncoded()));

        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                issuerDN, serialNumber, notBefore, notAfter, subjectDN,
                subjPubKeyInfo);
        DigestCalculator digCalc = null;
        try {
            digCalc = new BcDigestCalculatorProvider()
                    .get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
            X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(digCalc);
            // Subject Key Identifier
            certGen.addExtension(Extension.subjectKeyIdentifier, false,
                    x509ExtensionUtils.createSubjectKeyIdentifier(subjPubKeyInfo));
            // Authority Key Identifier
            certGen.addExtension(Extension.authorityKeyIdentifier, false,
                    x509ExtensionUtils.createAuthorityKeyIdentifier(subjPubKeyInfo));
            // Key Usage
            certGen.addExtension(Extension.keyUsage, false, new KeyUsage(
                    KeyUsage.dataEncipherment));
            if (crlUri != null) {
                // CRL Distribution Points
                DistributionPointName distPointOne = new DistributionPointName(
                        new GeneralNames(new GeneralName(
                                GeneralName.uniformResourceIdentifier,
                                crlUri)));

                DistributionPoint[] distPoints = new DistributionPoint[1];
                distPoints[0] = new DistributionPoint(distPointOne, null, null);
                certGen.addExtension(Extension.cRLDistributionPoints, false,
                        new CRLDistPoint(distPoints));
            }

            // Content Signer
            ContentSigner sigGen = new JcaContentSignerBuilder(
                    getSignAlgorithm()).setProvider(getProviderName()).build(privateKey);
            // Certificate
            return new JcaX509CertificateConverter()
                    .setProvider(getProviderName()).getCertificate(certGen.build(sigGen));
        } catch (Exception e) {
           throw new CryptoException(e);
        }

    }

    @Override
    public void writeCertificate(Writer pemWriter, X509Certificate selfCert) throws IOException {
        JcaPEMWriter certWriter = new JcaPEMWriter(pemWriter);
        certWriter.writeObject(selfCert);
        certWriter.flush();
        certWriter.close();
    }

    @Override
    public byte[] hash(byte[] input) {
        SHA3.DigestSHA3 md = new SHA3.DigestSHA3(512);
        md.update(input);
        return md.digest();
    }

    @Override
    public final PublicKey extractPublicKey(Reader pemReader) throws CryptoException {
        return extractCertificate(pemReader).getPublicKey();
    }

    @Override
    public X509Certificate extractCertificate(Reader pemReader) throws CryptoException {
        try {
            PEMParser parser = new PEMParser(pemReader);
            Object object = parser.readObject();
            pemReader.close();
            parser.close();
            if (object instanceof X509CertificateHolder) {
                X509CertificateHolder x509Holder = (X509CertificateHolder) object;
                return new JcaX509CertificateConverter().setProvider(getProviderName())
                        .getCertificate(x509Holder);
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
        return "BC";
    }

    @Override
    public String getCryptoAlgorithm() {
        return "RSA/ECB/PKCS1Padding";
    }

    @Override
    public String getSignAlgorithm() {
        return "SHA1WithRSA";
    }

    @Override
    public KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator
                    .getInstance("RSA");
            keyPairGenerator.initialize(2048);
            java.security.KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return keyPair;
        } catch (NoSuchAlgorithmException e) {
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

    @Override
    public byte[] base64Encode(byte[] toEncode) {
        return Base64.encode(toEncode);
    }

    @Override
    public byte[] base64Decode(byte[] toDecode) {
        return Base64.decode(toDecode);
    }


}
