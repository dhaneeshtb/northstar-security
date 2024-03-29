package org.northstar.security;

import com.fasterxml.jackson.annotation.JsonIgnore;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class GenerateKeyPair {

    private static final String BASE_ALGORITHM = "RSA";
    private static KeyFactory factory;
    private static KeyPairGenerator keyGenerator;

    private GenerateKeyPair(){}

    private static KeyFactory getFactory() throws NoSuchAlgorithmException {
        if (factory == null) {
            factory = KeyFactory.getInstance(BASE_ALGORITHM);
        }
        return factory;
    }

    private static KeyPairGenerator getGenerator() throws NoSuchAlgorithmException {
        if (keyGenerator == null) {
            keyGenerator = KeyPairGenerator.getInstance(BASE_ALGORITHM);
        }
        return keyGenerator;
    }



    private static String generateEncodedKey(String type,byte[] content) throws IOException {
        StringWriter privateKeyWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(privateKeyWriter);
        pemWriter.writeObject(new PemObject(type, content));
        pemWriter.flush();
        pemWriter.close();
        return privateKeyWriter.toString();
    }

    public static EncodedKeyPair generateKeyPair() throws IOException, NoSuchAlgorithmException {
        KeyPairGenerator generator = getGenerator();
        generator.initialize(4096);
        KeyPair pair = generator.generateKeyPair();
        String privateKeyString = generateEncodedKey("PRIVATE KEY",pair.getPrivate().getEncoded());
        String publicKeyWriterString =generateEncodedKey("PUBLIC KEY",pair.getPublic().getEncoded());
        return new EncodedKeyPair(privateKeyString, publicKeyWriterString);
    }

    public static EncodedKeyPair generateKeyPair(String privateKeyString,String publicKeyWriterString) throws  NoSuchAlgorithmException {
        KeyPairGenerator generator = getGenerator();
        generator.initialize(4096);
        return new EncodedKeyPair(privateKeyString, publicKeyWriterString);
    }

    public static DecodedKeyPair decodeKeyPair(EncodedKeyPair encodedKeyPair) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        return new DecodedKeyPair(readPKCS8PrivateKey(encodedKeyPair.getPrivateKey()),readX509PublicKey(encodedKeyPair.getPublicKey()));
    }

    public static RSAPublicKey readX509PublicKey(String encodedPublicKey) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory keyFactory = getFactory();
        PemReader pemReader = new PemReader(new StringReader(encodedPublicKey));
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pemReader.readPemObject().getContent());
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    public static RSAPrivateKey readPKCS8PrivateKey(String privateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = getFactory();
        PemReader pemReader = new PemReader(new StringReader(privateKey));
        PemObject pemObject = pemReader.readPemObject();
        byte[] content = pemObject.getContent();
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
        return (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);
    }

    public static class EncodedKeyPair {
        private  String privateKey;
        private  String publicKey;
        public EncodedKeyPair(String privateKey, String publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
        public EncodedKeyPair(){}
        public String getPrivateKey() {
            return privateKey;
        }
        public String getPublicKey() {
            return publicKey;
        }

        @JsonIgnore
        public DecodedKeyPair getDecodedPair() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            return GenerateKeyPair.decodeKeyPair(this);
        }
    }
    public static class DecodedKeyPair {
        private final RSAPrivateKey privateKey;
        private final RSAPublicKey publicKey;
        public DecodedKeyPair(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
        public RSAPrivateKey getPrivateKey() {
            return privateKey;
        }
        public RSAPublicKey getPublicKey() {
            return publicKey;
        }
    }


}
