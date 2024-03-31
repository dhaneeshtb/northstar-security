package org.northstar.security;

import org.junit.Assert;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class ContentEncryptionTest {

    @Test
    public void testEncrypt() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException {
       GenerateKeyPair.EncodedKeyPair serverKeyPair=GenerateKeyPair.generateKeyPair();
       String randomPassword = CryptoUtils.getRandomPassword(20);
       ContentEncryption ce=new ContentEncryption.ContentEncryptionBuilder(serverKeyPair,serverKeyPair.getDecodedPair())
                .withPassword(randomPassword)
                .build();
       String toEncrypt = "test";
       ByteBuffer encrypted= ce.encrypt2Buffer("test");
       String decryptedText = new String(ce.decryptContent(encrypted), StandardCharsets.UTF_8);
       Assert.assertEquals(toEncrypt,decryptedText);
    }

    @Test
    public void testEncryptWithClientToken() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException {
        GenerateKeyPair.EncodedKeyPair serverKeyPair=GenerateKeyPair.generateKeyPair();
        String randomPassword = CryptoUtils.getRandomPassword(10);
        String clientRawKey = CryptoUtils.getRandomPassword(10);
        RSADriver driverClient = new RSADriver();
        String clientEncryptedKey = driverClient.encryptAndEncodeAsString(clientRawKey.getBytes(StandardCharsets.UTF_8),serverKeyPair.getDecodedPair().getPublicKey());
        ContentEncryption ce=new ContentEncryption.ContentEncryptionBuilder(serverKeyPair,serverKeyPair.getDecodedPair())
                .withPassword(randomPassword)
                .withClientKey(clientEncryptedKey)
                .build();
        String toEncrypt = "test";
        ByteBuffer encrypted= ce.encrypt2Buffer("test");
        String decryptedText = new String(ce.decryptContent(encrypted));
        Assert.assertEquals(toEncrypt,decryptedText);


//        int keyContentLength= encrypted.getInt();
//        int payloadContentLength =  encrypted.getInt();
//        byte[] keyContent = new byte[keyContentLength];
//        encrypted.get(keyContent);
//        RSADriver driverClient1 = new RSADriver(CryptoConstants.CIPHER_SCHEME_INVERTED);
//        //Decrypt with server publicKey
//        String content= new String(driverClient1.decrypt(Base64.getDecoder().decode(keyContent),serverKeyPair.getDecodedPair().getPublicKey()),StandardCharsets.UTF_8);
//        System.out.println(content);
    }

    @Test
    public void testEncryptWithClientTokenAndClientCert() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException {
        GenerateKeyPair.EncodedKeyPair serverKeyPair=GenerateKeyPair.generateKeyPair();
        GenerateKeyPair.EncodedKeyPair clientCertPair=GenerateKeyPair.generateKeyPair();

        String randomPassword = CryptoUtils.getRandomPassword(10);
        String clientRawKey = CryptoUtils.getRandomPassword(10);
        RSADriver driverClient = new RSADriver();
        String clientEncryptedKey = driverClient.encryptAndEncodeAsString(clientRawKey.getBytes(StandardCharsets.UTF_8),serverKeyPair.getDecodedPair().getPublicKey());


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


//        int keyContentLength= encrypted.getInt();
//        int payloadContentLength =  encrypted.getInt();
//        byte[] keyContent = new byte[keyContentLength];
//        encrypted.get(keyContent);
//        RSADriver driverClient1 = new RSADriver(CryptoConstants.CIPHER_SCHEME_INVERTED);
//        //Decrypt with server publicKey
//        String content= new String(driverClient1.decrypt(Base64.getDecoder().decode(keyContent),serverKeyPair.getDecodedPair().getPublicKey()),StandardCharsets.UTF_8);
//        System.out.println(content);
    }

}
