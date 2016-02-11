[![Build Status](https://travis-ci.org/p-acs/commons-crypto.svg?branch=master)](https://travis-ci.org/p-acs/commons-crypto) [![Coverage Status](https://coveralls.io/repos/github/p-acs/commons-crypto/badge.svg?branch=master)](https://coveralls.io/github/p-acs/commons-crypto?branch=master)



# Purpose

This library acts as a slim facade for common crypto operations. 

It is specifically designed to be security provider agnostic and hides the complexity of storage and retrieval of keypairs.

It offers logic for:

+ creation of X509Certificates
+ asymmetric encryption and decryption of data
+ asymmetric signing and verification of data
+ symmetric encryption and decryption with a passphrase
+ hybrid encryption and decryption with the possibility to encrypt for multiple public keys

If you are looking for a solution to secure your Android application, please have a look at 
[Seccoco](https://github.com/p-acs/seccoco-android), which builds on top of this library.


# Usage


## Implement the security provider interface

This library can work with different security providers and has therefore no dependency to any, you can decide what 
security provider to use and implement the necessary logic in the ```SecurityProviderConnector``` interface.

You can find example connectors for [Bouncycastle](https://github.com/bcgit/bc-java) and 
for  [Spongycastle](https://github.com/bcgit/bc-java) in the test sources.

    SecurityProviderConnector connector = new BCConnector();
    
## Create a certificate

### Create certificate for Alice

    StringWriter alicesPemWriter = new StringWriter();
    ByteArrayOutputStream alicesPkcs12Stream = new ByteArrayOutputStream();
    char[] alicesPassword = "alices_password".toCharArray();
    X509Certificate alicesCertificate = new Certificates(connector,"Your Product").create("alice",alicesPassword,
    alicesPemWriter, alicesPkcs12Stream);
    String alicesPem = alicesPemWriter.toString();
    byte[] alicesPkcs12 = alicesPkcs12Stream.toByteArray();
    
### Create certificate for Bob

    StringWriter bobsPemWriter = new StringWriter();
    ByteArrayOutputStream bobsPkcs12Stream = new ByteArrayOutputStream();
    char[] bobsPassword = "bobs_password".toCharArray();
    X509Certificate bobsCertificate = new Certificates(connector,"Your Product").create("bob",bobsPassword,
    bobsPemWriter, bobsPkcs12Stream);
    String bobsPem = bobsPemWriter.toString();
    byte[] bobsPkcs12 = bobsPkcs12Stream.toByteArray();

## Asymmetric crypto

    ByteArrayInputStream bobsPkcs12InputStream = new ByteArrayInputStream(bobsPkcs12);
    byte[] plainMessageFromAlice = "How are you? Alice".getBytes();
    AsymmetricCrypto asymmetricCrypto = new AsymmetricCrypto(connector);
    byte[] encryptedForBob = asymmetricCrypto.encrypt(plainMessageFromAlice, new StringReader(bobsPem));
    byte[] decryptedFromBob = asymmetricCrypto.decrypt(encryptedForBob, bobsPassword, bobsPkcs12InputStream);
    
## Hybrid crypto

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
    
## More examples

You can find the example above together with additional usage examples in the test sources.
 
