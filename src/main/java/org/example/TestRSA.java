package org.example;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class TestRSA {

    private static final String RSA_ALGORITHM = "RSA";
    private static final String PUBLIC_KEY_BASE64 =
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAryyduth8vn1/NscdENDB8zDzJoRx0bVcRuBmVfPGFzmAJ8v0DZ4CK7lG3TCSBNmaZZJ+NFEpSsrO5oMxC/1njlOUUzI/kyhYyExQI2uyWHNcG61IDUWF8JlU5jwHLp9vdVFycbbjp17VJgf3emBGUL/fCQzsmccBfAal9Jljc5iP6xRbeq6m2lYprdBfLEGf/tIoQrpY079t0Hc8Rt07SHLYbJRiFHXW56ts37g4qWVXO/PVMPucj9vgkkz5GaFx/k4kajHjGbwzTx4v/O+YXE0NRVwEDsfUDCEYUAJEJsyLGRV/CRyeiYuz+39+85r3MjEE+YLo+FCWcO7k+1h2yQIDAQAB";

    public static void main(String[] args) {
        try {
            // Initialisation de la clé publique
            PublicKey publicKey = loadPublicKey(PUBLIC_KEY_BASE64);

            // Message à chiffrer
            String data = "mon message clair";
            System.out.println("Message clair : " + data);

            // Chiffrement
            String encryptedData = encryptWithPublicKey(data, publicKey);
            System.out.println("Message chiffré (Base64) : " + encryptedData);

        } catch (Exception e) {
            System.err.println("Une erreur est survenue : " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Charge une clé publique à partir d'une chaîne Base64.
     *
     * @param base64Key La clé publique en Base64.
     * @return Une instance de PublicKey.
     * @throws Exception En cas d'erreur de chargement de la clé.
     */
    private static PublicKey loadPublicKey(String base64Key) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(base64Key);
        KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
        return keyFactory.generatePublic(new X509EncodedKeySpec(decodedKey));
    }

    /**
     * Chiffre un message avec une clé publique.
     *
     * @param data       Le message à chiffrer.
     * @param publicKey  La clé publique utilisée pour le chiffrement.
     * @return Le message chiffré encodé en Base64.
     * @throws Exception En cas d'erreur de chiffrement.
     */
    private static String encryptWithPublicKey(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}
