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

    public RSADriver(Key privateKey, Key publicKey) {
        this(false, privateKey, publicKey);
    }

    /***
     *
     * @param inverted true to indicate private encrypt and public decrypt. false indicates public encrypt and private decrypt
     * @param privateKey RSA Private key
     * @param publicKey RSA Public key
     */
    public RSADriver(boolean inverted, Key privateKey, Key publicKey) {
        this.inverted = inverted;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        if (inverted) {
            this.cipherPadding = CryptoConstants.CIPHER_SCHEME_INVERTED;
        } else {
            this.cipherPadding = CryptoConstants.CIPHER_SCHEME_STRAIGHT;
        }
        initDecryptCipher();
        initEncryptCipher();

    }

    public RSADriver() {
        this(CryptoConstants.CIPHER_SCHEME_STRAIGHT);
    }

    public RSADriver(String cipherPadding) {
        this.cipherPadding = cipherPadding;
        this.privateKey = null;
        this.publicKey = null;
        this.inverted = false;
    }

    private void initEncryptCipher() {
        try {
            encryptCipher = Cipher.getInstance(cipherPadding);
            encryptCipher.init(Cipher.ENCRYPT_MODE, inverted ? privateKey : publicKey);
        } catch (Exception e) {
            throw new SecurityException(e);
        }
    }

    private void initDecryptCipher() {
        try {
            decryptCipher = Cipher.getInstance(cipherPadding);
            decryptCipher.init(Cipher.DECRYPT_MODE, inverted ? publicKey : privateKey);
        } catch (Exception e) {
            throw new SecurityException(e);
        }
    }

    public String encryptAndEncodeAsString(byte[] blockToEncrypt) throws IllegalBlockSizeException, BadPaddingException {
        byte[] bytes = encryptCipher.doFinal(blockToEncrypt);
        return new String(Base64.getEncoder().encode(bytes));
    }


    public String encryptAndEncodeAsString(byte[] blockToEncrypt, Key key) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return new String(encryptAndEncode(blockToEncrypt, key), StandardCharsets.UTF_8);
    }

    public byte[] encryptAndEncode(byte[] blockToEncrypt, Key key) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return Base64.getEncoder().encode(encrypt(blockToEncrypt, key));
    }

    public byte[] encrypt(byte[] blockToEncrypt, Key key) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(cipherPadding);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(blockToEncrypt);
    }


    public byte[] decrypt(byte[] blockToEncrypt, Key key) throws IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(cipherPadding);
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(blockToEncrypt);
    }


    public String decryptDecodeAsString(String encryptedText) throws IllegalBlockSizeException, BadPaddingException {
        return new String(decrypt(Base64.getDecoder().decode(encryptedText)), StandardCharsets.UTF_8);
    }

    public byte[] decryptDecode(String encryptedText) throws IllegalBlockSizeException, BadPaddingException {
        return decrypt(Base64.getDecoder().decode(encryptedText));
    }

    public byte[] decrypt(byte[] encryptedContent) throws IllegalBlockSizeException, BadPaddingException {
        return decryptCipher.doFinal(encryptedContent);
    }

    public String decryptDecodeAsString(String decryptBlock, Key key) throws IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        return new String(decrypt(Base64.getDecoder().decode(decryptBlock), key), StandardCharsets.UTF_8);
    }
}
