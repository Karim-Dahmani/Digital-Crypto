package org.example;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class TestRSADecrypt {
    public static void main(String[] args) {
        try {
            // Initialize the key factory for RSA
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            // Private Key (Base64 encoded, no headers/footers)
            String key = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCvLJ262Hy+fX82xx0Q0MHzMPMmhHHRtVxG4GZV88YXOYAny/QNngIruUbdMJIE2Zplkn40USlKys7mgzEL/WeOU5RTMj+TKFjITFAja7JYc1wbrUgNRYXwmVTmPAcun291UXJxtuOnXtUmB/d6YEZQv98JDOyZxwF8BqX0mWNzmI/rFFt6rqbaVimt0F8sQZ/+0ihCuljTv23QdzxG3TtIcthslGIUddbnq2zfuDipZVc789Uw+5yP2+CSTPkZoXH+TiRqMeMZvDNPHi/875hcTQ1FXAQOx9QMIRhQAkQmzIsZFX8JHJ6Ji7P7f37zmvcyMQT5guj4UJZw7uT7WHbJAgMBAAECggEAA924Nw3c5iQrt2NgzaSaozaXwM6rgTVZFAQspGwwGWy4QPVlxxpcC4Fk6JZp1csq3SyegtXhU2umciMmS5ClxT5fx6l6pB5mPZ8LJbz6v3j/gpzdOjqOk82bUhMarxMiiQEcxX9QoIdqeaxmidmvs5iIegRCNIkJcozmNllffu2VqJVo9jy5CffSFY1F458xo116WcILK8F+X/CQzK7+8q+a2uAQUrtLezWebw0hgC1QKtQcukG56PCWoOzWO+TL/1w6uSdLSq7LG19qIA9TIk5pwJ8MQaMp+xreipOG5iBcP4MNZQJ2w0DvM9cmqQoV6MwY0Yj9Iwuv/0+SQxIdAQKBgQDAj+NFArpl677O2NoO9wZ5xkGXSpsZnhBNA/b53mTgtVuZAOKzktXAuMa/5gR95xrX/LSVmjnLLW+vrAQqJwOkjvhtUXpNVhfBJhD4NfV0DBMOT3+oPvSRpRIr2siQ/ZhC4ZM+O2DT3Jfcs/MINUaVyjsgwOW/6qdCKednOq/rgwKBgQDo4ktvBs5vUq/XVRNwVS5TE+gxGr4XYwSOa9bIjwUFUjbVWngx+efECnNkyTZ2tFd2cXaMVnbiwNkCwWxa/tLHCRCIRIl9D3NHlRDGmI+qQTogjBc/XzhIX2dE+xbj3AaNVjd5JYvU/bbN8FXux9NvDh5iX/Cm7GH+ggIdkXEGwwKBgQCsSpHgl1ZMByiMTr6ckS28G0Voppory59uKVP7sZ6058/zEDXG0mRqsWkzHg160SLVigfRq1J2lkrN9a0sQggiXsGsnjA9rgBHE1Yvn6fkk0EhlsPzt5CAGCAwGOtHv39SqB5kmiBCr6c5E9Ep0PE86NsKrU1j8AKDUpb3aC0rHQKBgQDcOCmm+uO5R5K6aFvybMpai0eVL7mz+dF0MCuyCfRwfLcXd+6TK8NrkYpfMxrKk2zltxOoT5cqg7xyq5+gSLnetwaoJU9yMGsNtLthYSDxma6y2madaZiab4UDKQETRZv4iR/58nRRW/5CrdNE8jdRHCPFWP4DiyJ7fksr1L3x6wKBgAfwaTS4+mDvmqt3VhYmyKb1srjFOchchiVqeoTVj3X9u82+UWbiA6Qt9SHyJwsRhxj1l3CJragLBGZLAe3UKRn5yGlKsFYqPTkyMelEQNtVnZ30pmT8l9sBf8RQKB9tjtqhA/Rzqpcb+6EcEN/t2iO3vOprAjMDHhKuMqac9Utp";

            // Decode and generate the private key
            byte[] decodedKey = Base64.getDecoder().decode(key);
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedKey));

            // Encrypted message (Base64 encoded)
            String encryptedData = "rol6t0gRiGv4ykVdWNSbJdWQ+yYSe4HvDzPPywD5IsNBrU+m57KwDOBhk0Gtvogh8qRS27El2oEa9JqSEnCgrIngR4tymGVEBo0VLdHV99QGcw+J1So7fBqd0TpBqu3ow4QVdO8vcGd32xuvmmicKhzfH7uK6TnpNdmAouI6GgZrZa/rIsW3o58YzOYWaZ6yf/jUQWUre6rEybx6+7idoahIbuQmCEkFGNowFPxq7ILz63UUFmQBkDU1urtgZ2roBAAqtOpHq/udyJcI0ZpchdNQ/5DHEt1oq5MfQfj5isphH/fegIXPAqW1ZYgukpu2nBUqcLyp4HTQnYWEFou2Wg==";

            // Initialize the cipher in decryption mode with the private key
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            // Decrypt the message
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
            System.out.println("Decrypted Message: " + new String(decryptedBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
