package org.northstar.security;



import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class AESUtils {
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";

    public static final String OUTPUT_FORMAT = "%-30s:%s";


    private AESUtils(){

    }
    // AES-GCM needs GCMParameterSpec
    public static byte[] encrypt(byte[] pText, SecretKey secret, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(CryptoConstants.TAG_LENGTH_BIT, iv));

        return cipher.doFinal(pText);

    }

    public static byte[] encrypt(byte[] pText, SecretKeySpec spec) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, spec.getSecretKey(), new GCMParameterSpec(CryptoConstants.TAG_LENGTH_BIT, spec.getIv()));
        if(spec.getAad()!=null) {
            byte[] aadTagData = spec.getAad().getBytes();
            cipher.updateAAD(aadTagData);
        }
        return cipher.doFinal(pText);
    }

    // prefix IV length + IV bytes to cipher text
    public static byte[] encryptWithPrefixIV(byte[] pText, SecretKey secret, byte[] iv) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] cipherText = encrypt(pText, secret, iv);
        return ByteBuffer.allocate(iv.length + cipherText.length)
                .put(iv)
                .put(cipherText)
                .array();

    }

    public static byte[] decrypt(byte[] cText, SecretKey secret, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(CryptoConstants.TAG_LENGTH_BIT, iv));
        return cipher.doFinal(cText);
    }

    public static byte[] decrypt(byte[] cText, SecretKeySpec secret) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret.getSecretKey(), new GCMParameterSpec(CryptoConstants.TAG_LENGTH_BIT, secret.getIv()));
        if(secret.getAad()!=null) {
            byte[] aad = secret.getAad().getBytes();
            cipher.updateAAD(aad);
        }
        return cipher.doFinal(cText);
    }

    public static byte[] decryptWithPrefixIV(byte[] cText, SecretKeySpec secret) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        ByteBuffer bb = ByteBuffer.wrap(cText);
        byte[] iv = new byte[secret.getIv().length];
        bb.get(iv);
        byte[] cipherText = new byte[bb.remaining()];
        bb.get(cipherText);
        return decrypt(cipherText, secret.getSecretKey(), iv);
    }
}


