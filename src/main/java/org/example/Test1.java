package org.example;

import org.example.encryption.CryptoUtilImpl;

import java.util.Arrays;

public class Test1 {

    public static void main(String[] args) {
        CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();
        String data = "Hello from Oujda>>>>";

        // Test Base64 Encoding and Decoding
        System.out.println("Base64 Encoding and Decoding:");
        String encode64 = cryptoUtil.encodeToBase64(data.getBytes());
        byte[] decode64 = cryptoUtil.decodeFromBase64(encode64);
        System.out.println("Encoded (Base64): " + encode64);
        System.out.println("Decoded (Base64): " + new String(decode64));
        System.out.println("***************************************************");

        // Test Base64 URL Encoding and Decoding
        System.out.println("Base64 URL-Safe Encoding and Decoding:");
        String encode64URL = cryptoUtil.encodeToBase64URL(data.getBytes());
        byte[] decode64URL = cryptoUtil.decodeFromBase64URL(encode64URL);
        System.out.println("Encoded (Base64 URL): " + encode64URL);
        System.out.println("Decoded (Base64 URL): " + new String(decode64URL));
        System.out.println("***************************************************");

        // Test Conversion to Byte Array
        System.out.println("Byte Array Representation:");
        byte[] dataByte = data.getBytes();
        System.out.println("Original Data as Bytes: " + Arrays.toString(dataByte));
        System.out.println("***************************************************");

        // Test Hex Encoding
        System.out.println("Hexadecimal Encoding:");
        String dataHex = cryptoUtil.encoderHex(dataByte);
        System.out.println("Encoded (Hex, DatatypeConverter): " + dataHex);
        String apacheHex = cryptoUtil.encoderToHexApacheCodec(dataByte);
        System.out.println("Encoded (Hex, Apache Codec): " + apacheHex);
        String nativeHex = cryptoUtil.encoderToHexNative(data.getBytes());
        System.out.println("Encoded (Hex, Native Formatter): " + nativeHex);
        System.out.println("***************************************************");

        // Optional: Test Invalid Base64 Decoding
        try {
            System.out.println("Testing Invalid Base64 Decoding:");
            cryptoUtil.decodeFromBase64("Invalid_Base64_String");
        } catch (IllegalArgumentException e) {
            System.out.println("Caught Exception: " + e.getMessage());
        }
    }
}
