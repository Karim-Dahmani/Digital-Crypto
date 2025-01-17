package org.example;

import org.example.encryption.CryptoUtilImpl;

import javax.crypto.SecretKey;
import java.util.Arrays;
import java.util.Base64;

public class SymmetricCrypto {
    public static void main(String[] args) throws Exception {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();

        // Générer une clé secrète
        SecretKey secretKey = cryptoUtil.generateKey("1234567890123456"); // 16 caractères pour AES-128
        System.out.println("Clé secrète (Base64):");
        System.out.println(Base64.getEncoder().encodeToString(secretKey.getEncoded()));

        // Message à chiffrer
        String data = "This is my message";
        System.out.println("Données originales:");
        System.out.println(data);

        // Chiffrement
        String encryptedData = cryptoUtil.encryptAES(data.getBytes(), secretKey);
        System.out.println("Données chiffrées (Base64):");
        System.out.println(encryptedData);

        // Déchiffrement
        byte[] decryptedData = cryptoUtil.decryptAES(Arrays.toString(Base64.getDecoder().decode(encryptedData)), secretKey);
        System.out.println("Données déchiffrées:");
        System.out.println(new String(decryptedData));
    }
}
