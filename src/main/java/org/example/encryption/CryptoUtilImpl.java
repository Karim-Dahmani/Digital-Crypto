package org.example.encryption;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

public class CryptoUtilImpl {

    private static final String AES_ALGORITHM = "AES";
    private static final String RSA_ALGORITHM = "RSA";
    private static final String AES_CIPHER = "AES/ECB/PKCS5Padding";

    public String encodeToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    public byte[] decodeFromBase64(String dataBase64) {
        return Base64.getDecoder().decode(dataBase64);
    }

    public String encodeToBase64URL(byte[] data) {
        return Base64.getUrlEncoder().encodeToString(data);
    }

    public byte[] decodeFromBase64URL(String dataBase64) {
        return Base64.getUrlDecoder().decode(dataBase64);
    }

    public String encoderHex(byte[] data) {
        return Hex.encodeHexString(data);
    }
    public String encoderToHexApacheCodec(byte[] data){
        return Hex.encodeHexString(data);
    }

    public String encoderToHexNative(byte[] data){

        Formatter formatter = new Formatter();

        for(byte b:data){
            formatter.format("%02x",b);
        }
        return formatter.toString();
    }

    public SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(AES_ALGORITHM);
        keyGenerator.init(128); // 128, 192, or 256
        return keyGenerator.generateKey();
    }

    public SecretKey generateKey(String secret) {
        if (secret.length() != 16 && secret.length() != 24 && secret.length() != 32) {
            throw new IllegalArgumentException("Invalid AES key length: must be 16, 24, or 32 bytes.");
        }
        return new SecretKeySpec(secret.getBytes(), AES_ALGORITHM);
    }

    public byte[] decryptAES(String encodedEncryptedData, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] encryptedData = decodeFromBase64(encodedEncryptedData);
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(encryptedData);
    }

    public String encryptAES(byte[] data, SecretKey secretKey)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(AES_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedData = cipher.doFinal(data);
        return encodeToBase64(encryptedData);
    }

    public KeyPair GenerateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        keyPairGenerator.initialize(2048); // Recommended key size
        return keyPairGenerator.generateKeyPair();
    }

    public PublicKey publicKeyFromBase64(String pkBase64) throws Exception {

        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        byte[] decode = Base64.getDecoder().decode(pkBase64);
        return keyFactory.generatePublic(new X509EncodedKeySpec(decode));
    }
    public PrivateKey privateKeyFromBase64(String privateKeyBase64) throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        byte[] decode = Base64.getDecoder().decode(privateKeyBase64);
        return  keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decode));
    }
    public String encryptRSA(byte[] data , PublicKey publicKey)throws Exception{
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    public byte[] decryptRSA(String encryptedData , PrivateKey privateKey)throws Exception{
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytes = decodeFromBase64(encryptedData);
        byte[] decryptedBytes = cipher.doFinal(bytes);
        return decryptedBytes;
    }
}
