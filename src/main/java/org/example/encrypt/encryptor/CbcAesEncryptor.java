package org.example.encrypt.encryptor;

import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.example.encrypt.cipher.AesCipher;
import org.example.encrypt.cipher.AesCipherFactory;
import org.example.encrypt.cipher.AesCipherFactoryProvider;

public class CbcAesEncryptor implements AesEncryptor {

    private static final int IV_LENGTH = 16;

    private final SecretKey secretKey;
    private final AesCipherFactory aesCipherFactory;

    public CbcAesEncryptor(String secretKey, AesCipherFactoryProvider aesCipherFactoryProvider) {
        this.secretKey = SecretKeyUtil.createAes(secretKey, AesBit.BIT256);
        this.aesCipherFactory = aesCipherFactoryProvider.provide("AES/CBC/PKCS5Padding");
    }

    @Override
    public String encrypt(String plainText) {
        AesCipher aesCipher = aesCipherFactory.get();
        byte[] iv = new byte[IV_LENGTH];
        ThreadLocalRandom.current().nextBytes(iv);
        var parameterSpec = new IvParameterSpec(iv);
        return Encoder.encodeHex(iv) + Encoder.encodeHex(aesCipher.encrypt(plainText, secretKey, parameterSpec));
    }

    @Override
    public String decrypt(String cipherText) {
        byte[] iv = extractIv(cipherText);
        if (iv == null) {
            return null;
        }
        var parameterSpec = new IvParameterSpec(iv);
        AesCipher aesCipher = aesCipherFactory.get();
        String cipherBytes = cipherText.substring(IV_LENGTH * 2);
        return aesCipher.decrypt(Encoder.decodeHex(cipherBytes), secretKey, parameterSpec);
    }

    private byte[] extractIv(String cipherText) {
        try {
            return Encoder.decodeHex(cipherText.substring(0, IV_LENGTH * 2));
        } catch (Exception e) {
            return null;
        }
    }
}
