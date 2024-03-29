package org.northstar.security;

import com.fasterxml.jackson.databind.ObjectMapper;

public class CryptoConstants {
    private CryptoConstants(){

    }
    public static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    public static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~`!@#$%^&*()-_=+[{]}\\|;:\'\",<.>/?";
    public static final  int AES_KEY_BYTES = 32;
    public static final  int IV_LENGTH_BYTE = 12;
    public static final  int TAG_LENGTH=16;

    public static final  int TAG_LENGTH_BIT=TAG_LENGTH*8;

    public static final  int AES_KEY_BITS=AES_KEY_BYTES*8;
    public static final int AES_ITERATION_COUNT = 100;

    public static final String CIPHER_SCHEME_STRAIGHT="RSA/NONE/OAEPWithSHA1AndMGF1Padding";

    public static final String CIPHER_SCHEME_INVERTED="RSA/NONE/PKCS1Padding";

}
