# northstar-security
Introducing our cutting-edge content encryption library, seamlessly integrating RSA and AES algorithms to safeguard your data with utmost security. Our library empowers developers to easily implement robust encryption mechanisms, ensuring confidentiality and integrity of sensitive information. With RSA for secure key exchange and AES for efficient symmetric encryption, our solution offers a versatile and reliable approach to protect your content across various platforms and applications. Trust in our encryption library to fortify your data against unauthorized access and breaches, providing peace of mind for you and your users
## Features

- **Easy to use**
- **End 2 end content security**

## Installation

To use NorthStar security in your Java project, you can include it as a dependency using Maven or Gradle.

**Maven:**
```xml
<dependency>
    <groupId>io.github.dhaneeshtb</groupId>
    <artifactId>northstar-security</artifactId>
    <version>1.0.0</version>
</dependency>

```

## Usage Examples

### 1. Simple Content Encryption with password
```java
        GenerateKeyPair.EncodedKeyPair serverKeyPair=GenerateKeyPair.generateKeyPair();
        String randomPassword = CryptoUtils.getRandomPassword(20);
        ContentEncryption ce=new ContentEncryption.ContentEncryptionBuilder(serverKeyPair,serverKeyPair.getDecodedPair())
        .withPassword(randomPassword)
        .build();
        String toEncrypt = "test";
        ByteBuffer encrypted= ce.encrypt2Buffer("test");
        String decryptedText = new String(ce.decryptContent(encrypted), StandardCharsets.UTF_8);
        Assert.assertEquals(decryptedText,out);

```

### 2. Content Encryption with password and client key

```java
        GenerateKeyPair.EncodedKeyPair serverKeyPair=GenerateKeyPair.generateKeyPair();
        String randomPassword = CryptoUtils.getRandomPassword(10);
        String clientRawKey = CryptoUtils.getRandomPassword(10);
        RSADriver driverClient = new RSADriver();
        String clientEncryptedKey = driverClient.encrypt(clientRawKey.getBytes(StandardCharsets.UTF_8),serverKeyPair.getDecodedPair().getPublicKey());
        ContentEncryption ce=new ContentEncryption.ContentEncryptionBuilder(serverKeyPair,serverKeyPair.getDecodedPair())
        .withPassword(randomPassword)
        .withClientKey(clientEncryptedKey)
        .build();
        String toEncrypt = "test";
        ByteBuffer encrypted= ce.encrypt2Buffer("test");
        String out = new String(ce.decryptContent(encrypted));
        Assert.assertEquals(toEncrypt,out);
```

### 3. Content Encryption with password and client key and client certificate

```java
        GenerateKeyPair.EncodedKeyPair serverKeyPair=GenerateKeyPair.generateKeyPair();
        GenerateKeyPair.EncodedKeyPair clientCertPair=GenerateKeyPair.generateKeyPair();

        String randomPassword = CryptoUtils.getRandomPassword(10);
        String clientRawKey = CryptoUtils.getRandomPassword(10);
        RSADriver driverClient = new RSADriver();
        String clientEncryptedKey = driverClient.encrypt(clientRawKey.getBytes(StandardCharsets.UTF_8),serverKeyPair.getDecodedPair().getPublicKey());


        ContentEncryption ce=new ContentEncryption.ContentEncryptionBuilder(serverKeyPair,serverKeyPair.getDecodedPair())
        .withPassword(randomPassword)
        .withClientKey(clientEncryptedKey)
        .withClientCert(clientCertPair.getPublicKey())
        .build();
        String toEncrypt = "test";
        ByteBuffer encrypted= ce.encrypt2Buffer("test");

        ContentEncryption ceDecrypt=new ContentEncryption.ContentEncryptionBuilder(serverKeyPair,serverKeyPair.getDecodedPair())
        .withPassword(randomPassword)
        .withClientKey(clientEncryptedKey)
        .withClientCert(clientCertPair.getPrivateKey())
        .build();

        String decryptedText = new String(ceDecrypt.decryptContent(encrypted));
        Assert.assertEquals(toEncrypt,decryptedText);
```

## Contributing
Contributions to NorthStar are welcome! If you find any issues or have suggestions for improvements, feel free to open an issue or submit a pull request on GitHub.


## License
MIT

## Support
For any inquiries or support, you can contact the maintainers at dhaneeshtnair@gmail.com.

