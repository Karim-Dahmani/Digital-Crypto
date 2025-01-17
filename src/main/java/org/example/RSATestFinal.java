package org.example;

import org.example.encryption.CryptoUtilImpl;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSATestFinal {

    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();

        // Generate RSA key pair
        KeyPair keyPair = cryptoUtil.GenerateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encode keys to Base64
        String pkBase64 = cryptoUtil.encodeToBase64(publicKey.getEncoded());
        System.out.println("Public Key (Base64): " + pkBase64);

        String pvkBase64 = cryptoUtil.encodeToBase64(privateKey.getEncoded());
        System.out.println("Private Key (Base64): " + pvkBase64);

        // Data to be encrypted
        String data = "Hello again";

        // Decode keys from Base64
        PublicKey publicKey1 = cryptoUtil.publicKeyFromBase64(pkBase64);
        PrivateKey privateKey1 = cryptoUtil.privateKeyFromBase64(pvkBase64);

        // Encrypt the data using the public key
        String encryptedRSA = cryptoUtil.encryptRSA(data.getBytes(), publicKey1);
        System.out.println("------- Encrypted RSA -----------");
        System.out.println(encryptedRSA);

        // Decrypt the encrypted data using the private key
        byte[] decryptedBytes = cryptoUtil.decryptRSA(encryptedRSA, privateKey1);
        String decryptedRSA = new String(decryptedBytes);
        System.out.println("------- Decrypted RSA -----------");
        System.out.println(decryptedRSA);
    }
}
