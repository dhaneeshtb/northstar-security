package org.northstar.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.bouncycastle.pqc.legacy.math.linearalgebra.CharUtils;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Map;

public class SecretKeySpec {

    private char[] password;

    public String getAad() {
        return aad;
    }

    public void setAad(String aad) {
        this.aad = aad;
    }

    private byte[] salt;

    private String aad;

    public Map<String, Integer> getConstants() {
        return constants;
    }

    private Map<String,Integer> constants=Map.of("KEY_LENGTH",CryptoConstants.AES_KEY_BYTES,"IV_LENGTH",CryptoConstants.IV_LENGTH_BYTE,"TAG_LENGTH",CryptoConstants.TAG_LENGTH,"ITERATION_COUNT",CryptoConstants.AES_ITERATION_COUNT);


    @JsonIgnore
    private SecretKey secretKey = null;
    private byte[] iv;

    @JsonIgnore
    private String encodedKey = null;

    public String getEncodedKey() {
        return encodedKey;
    }

    public void setEncodedKey(String encodedKey) {
        this.encodedKey = encodedKey;
    }

    public char[] getPassword() {
        return password;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getIv() {
        return iv;
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }
    public SecretKeySpec(){

    }

    public SecretKeySpec(char[] password, byte[] salt) throws SecurityException {
        this.password = password;
        this.salt = salt;
        try {
            iv=  CryptoUtils.getRandomNonce(CryptoConstants.IV_LENGTH_BYTE);
            initKey(null);
        } catch (Exception e) {
            throw new SecurityException(e);
        }

    }

    public SecretKeySpec(char[] password) throws SecurityException {
        this(password,CryptoUtils.getRandomNonce(32));

    }

    private void initKey(String clentKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if(secretKey==null) {
            password = clentKey!=null && !clentKey.isEmpty() ? (clentKey+new String(password)).toCharArray():password;
            secretKey = CryptoUtils.getAESKeyFromPassword(password, salt);
            encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        }
    }

    public static SecretKeySpec randomKey() throws SecurityException {
        try {
            String pwd = CryptoUtils.getRandomPassword( 15);
            return new SecretKeySpec(pwd.toCharArray(),CryptoUtils.getRandomNonce(32));
        } catch (Exception e) {
            throw new SecurityException(e);
        }
    }

    public static SecretKeySpec toSpec(String seialString) throws SecurityException {
        try {
            SecretKeySpec spec= CryptoConstants.OBJECT_MAPPER.readValue(seialString,SecretKeySpec.class);
            spec.initKey(null);
            return spec;
        } catch (Exception e) {
            throw new SecurityException(e);
        }
    }

    public static SecretKeySpec toSpec(String seialString,String clientKey) throws SecurityException {
        try {
            SecretKeySpec spec= CryptoConstants.OBJECT_MAPPER.readValue(seialString,SecretKeySpec.class);
            spec.initKey(clientKey);
            return spec;
        } catch (Exception e) {
            throw new SecurityException(e);
        }
    }




}