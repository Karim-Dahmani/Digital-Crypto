package org.example;

import org.example.encryption.CryptoUtilImpl;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class GenerateRSAKeys {

    public static void displayRSAKeys() throws Exception {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();

        // Generate RSA key pair
        KeyPair keyPair = cryptoUtil.GenerateKeyPair();

        // Extract the private and public keys
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Display the private and public keys
        System.out.println("Private Key:");
        System.out.println(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        System.out.println("--------------------");
        System.out.println("Public Key:");
        System.out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        // Display key lengths
        System.out.println("--------------------");
        System.out.println("Private Key Length: " + privateKey.getEncoded().length * 8 + " bits");
        System.out.println("Public Key Length: " + publicKey.getEncoded().length * 8 + " bits");
    }

    public static void main(String[] args) {
        try {
            displayRSAKeys();
        } catch (Exception e) {
            System.err.println("An error occurred while generating RSA keys: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
