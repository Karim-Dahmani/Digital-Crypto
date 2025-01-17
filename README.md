# Digital-Crypto
# CryptoUtil - Cryptographic Utility Library

## Overview

`CryptoUtil` is a utility library for performing common cryptographic operations such as encryption, decryption, and encoding in Java. This library offers a set of methods that support:
- AES encryption/decryption
- RSA key pair generation
- Base64 and Hex encoding/decoding (both standard and URL-safe)

This project simplifies the integration of cryptographic functionality in Java applications by providing a simple and reusable API for various cryptographic operations.

## Features

- **AES Encryption/Decryption**: Securely encrypt and decrypt data using AES encryption with a secret key.
- **RSA Key Pair Generation**: Generate public/private RSA key pairs for secure communication.
- **Base64 Encoding/Decoding**: Convert data into Base64 format for easy transmission and storage.
- **Hex Encoding/Decoding**: Convert binary data into its hexadecimal representation, useful for debugging and logging.

## Prerequisites

To use this library, you'll need:

- **JDK 8 or higher**
- **Apache Commons Codec** (for Hex encoding/decoding)

## How It Works

### Base64 Encoding and Decoding

Base64 encoding is a method of converting binary data into a text format, which is commonly used for encoding binary data in a way that can be transmitted over text-based protocols like HTTP.

#### Methods:
- **encodeToBase64(byte[] data)**: Converts binary data into a Base64-encoded string.
- **decodeFromBase64(String base64Data)**: Decodes a Base64-encoded string back into binary data.
- **encodeToBase64URL(byte[] data)**: Encodes data in Base64 using URL-safe characters.
- **decodeFromBase64URL(String base64Data)**: Decodes a URL-safe Base64 string back into binary data.

### Hex Encoding and Decoding

Hex encoding is often used to represent binary data in a human-readable form. Each byte is represented by two characters (the hexadecimal digits).

#### Methods:
- **encoderHex(byte[] data)**: Converts binary data to a Hex string using the Apache Commons Codec library.
- **encoderToHexNative(byte[] data)**: Converts binary data to a Hex string using native Java code.

### AES Encryption and Decryption

AES (Advanced Encryption Standard) is one of the most widely used symmetric encryption algorithms. The `CryptoUtil` class provides methods to encrypt and decrypt data using AES with a secret key.

#### Methods:
- **generateKey()**: Generates a new AES key (128-bit).
- **generateKey(String secret)**: Generates an AES key from a provided secret string (must be 16, 24, or 32 bytes long).
- **encryptAES(byte[] data, SecretKey secretKey)**: Encrypts data using AES and a secret key.
- **decryptAES(String encodedEncryptedData, SecretKey secretKey)**: Decrypts AES-encrypted data using a secret key.

### RSA Key Pair Generation

RSA (Rivest–Shamir–Adleman) is an asymmetric cryptography algorithm that uses a pair of keys: a public key and a private key. RSA is commonly used for secure data transmission.

#### Methods:
- **GenerateKeyPair()**: Generates an RSA key pair (public and private key) with a key size of 2048 bits.

## Usage Example

Here is an example of how to use the `CryptoUtilImpl` class to perform common cryptographic operations:

### Base64 Encoding and Decoding

```java
CryptoUtilImpl cryptoUtil = new CryptoUtilImpl();

// Base64 encoding
String encoded = cryptoUtil.encodeToBase64("Hello, Crypto!".getBytes());
System.out.println("Base64 Encoded: " + encoded);

// Base64 decoding
byte[] decoded = cryptoUtil.decodeFromBase64(encoded);
System.out.println("Decoded: " + new String(decoded));
