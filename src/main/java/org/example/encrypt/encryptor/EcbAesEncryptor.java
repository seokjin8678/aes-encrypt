package org.example.encrypt.encryptor;

import javax.crypto.SecretKey;
import org.example.encrypt.cipher.AesCipher;
import org.example.encrypt.cipher.AesCipherFactory;
import org.example.encrypt.cipher.AesCipherFactoryProvider;

public class EcbAesEncryptor implements AesEncryptor {

    private final SecretKey secretKey;
    private final AesCipherFactory aesCipherFactory;

    public EcbAesEncryptor(String secretKey, AesCipherFactoryProvider aesCipherFactoryProvider) {
        this.secretKey = SecretKeyUtil.createAes(secretKey, AesBit.BIT256);
        this.aesCipherFactory = aesCipherFactoryProvider.provide("AES/ECB/PKCS5Padding");
    }

    @Override
    public String encrypt(String plainText) {
        AesCipher aesCipher = aesCipherFactory.get();
        return Encoder.encodeHex(aesCipher.encrypt(plainText, secretKey, null));
    }

    @Override
    public String decrypt(String cipherText) {
        AesCipher aesCipher = aesCipherFactory.get();
        return aesCipher.decrypt(Encoder.decodeHex(cipherText), secretKey, null);
    }
}
