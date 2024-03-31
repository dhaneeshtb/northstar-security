package org.northstar.security;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.northstar.security.exception.SecurityException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class ContentEncryption {

    GenerateKeyPair.EncodedKeyPair keyPair = null;
    GenerateKeyPair.DecodedKeyPair keyPairDecoded = null;
    SecretKeySpec keySpec = SecretKeySpec.randomKey();
    private RSADriver rsaDriverStraight;
    private String password = null;
    private String clientKey = null;
    private boolean includeClientKey;
    private RSADriver rsaDriver;
    private String clientCert;


    public ContentEncryption(String privateKey, String publicKey, boolean inverted) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        keyPair = GenerateKeyPair.generateKeyPair(privateKey, publicKey);
        keyPairDecoded = GenerateKeyPair.decodeKeyPair(keyPair);
        initStraighRSADriver(inverted);
    }

    public ContentEncryption(GenerateKeyPair.EncodedKeyPair encodedKeyPair, GenerateKeyPair.DecodedKeyPair decodedKeyPair, boolean inverted) {
        this.keyPair = encodedKeyPair;
        this.keyPairDecoded = decodedKeyPair;
        initStraighRSADriver(inverted);

    }

    public ContentEncryption(boolean inverted) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        keyPair = GenerateKeyPair.generateKeyPair();
        keyPairDecoded = GenerateKeyPair.decodeKeyPair(keyPair);
        initStraighRSADriver(inverted);
    }


    public static ByteBuffer fromInputStrem(InputStream is) throws IOException {
        return ByteBuffer.wrap(is.readAllBytes());
    }

    public static ByteBuffer bufferFile(File file) throws IOException {
        long size = file.length();
        ByteBuffer buf = ByteBuffer.allocate((int) (size & 0x7FFFFFFF));
        try(FileInputStream fis=new FileInputStream(file);FileChannel chan = fis.getChannel()) {
            while (buf.remaining() > 0) {
                int n = chan.read(buf);
                if (n <= 0) throw new IOException("Read operation failed.");
            }
        }
        return buf;
    }



    private static void writeBufferToFile(String filePath, ByteBuffer byteBuffer) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            FileChannel fc = fos.getChannel();
            fc.write(byteBuffer);
            fc.close();
        }
    }

    private static ByteBuffer createEncryptedBuffer(byte[] encryptedContent, byte[] encryptedKey) {
        int totalLength = encryptedKey.length + encryptedContent.length;
        ByteBuffer byteBuffer = ByteBuffer.allocate(totalLength + 8);
        byteBuffer.putInt(encryptedKey.length);
        byteBuffer.putInt(encryptedContent.length);
        byteBuffer.put(encryptedKey);
        byteBuffer.put(encryptedContent);
        byteBuffer.flip();
        return byteBuffer;
    }

    private static String readFileContent(String pathToFile) throws IOException {
        return new String(Files.readAllBytes(Paths.get(pathToFile)));
    }

    private void initStraighRSADriver(boolean inverted) {
        rsaDriver = new RSADriver(inverted, keyPairDecoded.getPrivateKey(), keyPairDecoded.getPublicKey());
        rsaDriverStraight = new RSADriver(keyPairDecoded.getPrivateKey(), keyPairDecoded.getPublicKey());
    }

    public void encryptFile(String pathSource, String pathTarget) throws SecurityException {
        try {
            ByteBuffer buffer = encryptFile2Buffer(pathSource);
            writeBufferToFile(pathTarget, buffer);
        } catch (Exception e) {
            throw new SecurityException(e);
        }
    }

    public ByteBuffer encryptFile2Buffer(String filePathToEncrypt) throws SecurityException {
        try {
            return encrypt2Buffer(readFileContent(filePathToEncrypt));
        } catch (Exception e) {
            throw new SecurityException(e);
        }
    }

    public ByteBuffer encrypt2Buffer(String contentString) throws SecurityException {
        try {
            ObjectNode node = CryptoConstants.OBJECT_MAPPER.valueToTree(keySpec);
            if (includeClientKey) {
                node.put("password", password);
            }
            String encryptedText;
            byte[] toEncrypt=node.toString().getBytes(StandardCharsets.UTF_8);
            if(clientCert!=null){
                encryptedText =  new RSADriver().encryptAndEncodeAsString(toEncrypt,GenerateKeyPair.readX509PublicKey(clientCert));
            }else{
                encryptedText = rsaDriver.encryptAndEncodeAsString(toEncrypt);
            }
            byte[] content = AESUtils.encrypt(contentString.getBytes(StandardCharsets.UTF_8), keySpec);
            return createEncryptedBuffer(content, encryptedText.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            throw new SecurityException(e);
        }
    }

    public byte[] decryptContent(byte[] content) throws SecurityException {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(content);
            return decryptContent(buffer);
        } catch (Exception e) {
            throw new SecurityException(e);
        }
    }

    public byte[] decryptContent(InputStream is) throws SecurityException {
        try {
            return decryptContent(fromInputStrem(is));
        } catch (Exception e) {
            throw new SecurityException(e);
        }
    }

    public byte[] decryptContent(String content) {
        return decryptContent(content.getBytes(StandardCharsets.UTF_8));
    }

    public byte[] decryptFile(String filePathToDecrypt)  {
        try {
            ByteBuffer buffer = bufferFile(new File(filePathToDecrypt));
            return decryptContent(buffer);
        }catch (Exception e){
            throw new SecurityException(e);
        }

    }

    public byte[] decryptContent(ByteBuffer buffer) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, SecurityException, IOException, InvalidKeySpecException {
        buffer.rewind();
        int keylength = buffer.getInt();
        int contentLength = buffer.getInt();
        byte[] keySpecText = new byte[keylength];
        byte[] content = new byte[contentLength];
        buffer.get(keySpecText);
        buffer.get(content);
        SecretKeySpec keySpecLocal;
        RSADriver decryptDriver = clientCert!=null?new RSADriver():rsaDriver;
        if(clientCert!=null){
            keySpecLocal = SecretKeySpec.toSpec(decryptDriver.decryptDecodeAsString(new String(keySpecText, StandardCharsets.UTF_8),GenerateKeyPair.readPKCS8PrivateKey(clientCert)), clientKey);
        }else {
            keySpecLocal = SecretKeySpec.toSpec(decryptDriver.decryptDecodeAsString(new String(keySpecText, StandardCharsets.UTF_8)), clientKey);
        }
        return AESUtils.decrypt(content, keySpecLocal);
    }

    public static class ContentEncryptionBuilder {

        private GenerateKeyPair.DecodedKeyPair decodedKeyPair;
        private GenerateKeyPair.EncodedKeyPair encodedKeyPair;
        private String privateKey;
        private String publicKey;

        private String password = null;
        private String clientKey = null;
        private boolean includeClientKey;
        private boolean inverted;
        private String clientCert;

        public ContentEncryptionBuilder(String privateKey, String publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public ContentEncryptionBuilder(GenerateKeyPair.EncodedKeyPair encodedKeyPair, GenerateKeyPair.DecodedKeyPair decodedKeyPair) {
            this.encodedKeyPair = encodedKeyPair;
            this.decodedKeyPair = decodedKeyPair;
        }

        public ContentEncryptionBuilder withPassword(String password) {
            this.password = password;
            return this;
        }

        public ContentEncryptionBuilder withClientKey(String clientKey) {
            if(clientKey!=null) {
                this.clientKey = clientKey;
                this.includeClientKey = true;
            }
            return this;
        }

        public ContentEncryptionBuilder withInverted(boolean inverted) {
            this.inverted = inverted;
            return this;
        }


        public ContentEncryption build() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, IllegalBlockSizeException, BadPaddingException {
            ContentEncryption ce = privateKey != null && publicKey != null ? new ContentEncryption(privateKey, publicKey, inverted) : new ContentEncryption(encodedKeyPair, decodedKeyPair, inverted);
            ce.includeClientKey = includeClientKey;
            ce.password = password;

            if(clientCert!=null) {
                ce.clientCert = clientCert;
            }
            if (includeClientKey) {
                ce.clientKey= clientKey.length()<30?clientKey: ce.rsaDriverStraight.decryptDecodeAsString(clientKey);
                ce.password = CryptoUtils.getRandomPassword(10);
                ce.keySpec = new SecretKeySpec((ce.clientKey + ce.password).toCharArray());
            }else{
                if(ce.password==null){
                    ce.password = CryptoUtils.getRandomPassword(10);
                }
                ce.keySpec = new SecretKeySpec(ce.password.toCharArray());
            }
            ce.keySpec.setAad(CryptoUtils.getRandomPassword(20));
            return ce;
        }

        public ContentEncryptionBuilder withClientCert(String clientCert) {
            this.clientCert=clientCert;
            return this;
        }
    }


}
