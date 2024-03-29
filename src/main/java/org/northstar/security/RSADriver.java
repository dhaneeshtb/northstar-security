package org.northstar.security;

import org.northstar.security.exception.SecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;

public class RSADriver {
    private static final Logger LOGGER = LoggerFactory.getLogger(RSADriver.class);

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    private final Key privateKey;
    private final boolean inverted;
    private final Key publicKey;
    private final String cipherPadding;

    private Cipher encryptCipher;
    private Cipher decryptCipher;

    public RSADriver(Key privateKey,Key publicKey){
        this(false,privateKey,publicKey);
    }
    public RSADriver(boolean inverted,Key privateKey,Key publicKey){
        this.inverted= inverted;
        this.privateKey=privateKey;
        this.publicKey=publicKey;
        if(inverted) {
            this.cipherPadding = CryptoConstants.CIPHER_SCHEME_INVERTED;
        }else{
            this.cipherPadding = CryptoConstants.CIPHER_SCHEME_STRAIGHT;
        }
        initDecryptCipher();
        initEncryptCipher();

    }
    public RSADriver(){
        this(CryptoConstants.CIPHER_SCHEME_STRAIGHT);
    }

    public RSADriver(String cipherPadding){
        this.cipherPadding = cipherPadding;
        this.privateKey=null;
        this.publicKey=null;
        this.inverted=false;
    }
    private void initEncryptCipher(){
        try {
            encryptCipher = Cipher.getInstance(cipherPadding);
            encryptCipher.init(Cipher.ENCRYPT_MODE, inverted? privateKey: publicKey);
        } catch (Exception e) {
            throw new SecurityException(e);
        }
    }

    private void initDecryptCipher(){
        try {
            decryptCipher = Cipher.getInstance(cipherPadding);
            decryptCipher.init(Cipher.DECRYPT_MODE, inverted? publicKey: privateKey);
        } catch (Exception e) {
            throw new SecurityException(e);
        }
    }

    public  String encrypt(byte[] blockToEncrypt) throws IllegalBlockSizeException, BadPaddingException {
        byte[] bytes = encryptCipher.doFinal(blockToEncrypt);
        return new String(Base64.getEncoder().encode(bytes));
    }
    public  String decrypt(String encryptedText) throws IllegalBlockSizeException, BadPaddingException {
        byte[] bytes = decryptCipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(bytes, StandardCharsets.UTF_8);
    }

    public  String decrypt(byte[] encryptedContent) throws IllegalBlockSizeException, BadPaddingException {
        byte[] bytes = decryptCipher.doFinal(encryptedContent);
        return new String(bytes,StandardCharsets.UTF_8);
    }

    public  String encrypt(byte[] blockToEncrypt,Key key) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(cipherPadding);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = cipher.doFinal(blockToEncrypt);
        return new String(Base64.getEncoder().encode(bytes),StandardCharsets.UTF_8);
    }

    public  byte[] decrypt(byte[] blockToEncrypt,Key key) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(cipherPadding);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(blockToEncrypt);
    }

    public  String decrypt(String decryptBlock,Key key) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return new String(decrypt(Base64.getDecoder().decode(decryptBlock),key),StandardCharsets.UTF_8);
    }
}
