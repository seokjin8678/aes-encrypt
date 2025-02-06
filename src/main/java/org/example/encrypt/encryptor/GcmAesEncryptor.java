package org.example.encrypt.encryptor;

import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.example.encrypt.cipher.AesCipher;
import org.example.encrypt.cipher.AesCipherFactory;
import org.example.encrypt.cipher.AesCipherFactoryProvider;

public class GcmAesEncryptor implements AesEncryptor {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_BIT_LENGTH = 128;

    private final SecretKey secretKey;
    private final AesCipherFactory aesCipherFactory;

    public GcmAesEncryptor(String secretKey, AesCipherFactoryProvider aesCipherFactoryProvider) {
        this.secretKey = SecretKeyUtil.createAes(secretKey, AesBit.BIT256);
        this.aesCipherFactory = aesCipherFactoryProvider.provide("AES/GCM/NoPadding");
    }

    @Override
    public String encrypt(String plainText) {
        AesCipher aesCipher = aesCipherFactory.get();
        byte[] iv = new byte[GCM_IV_LENGTH];
        ThreadLocalRandom.current().nextBytes(iv);
        var parameterSpec = new GCMParameterSpec(GCM_BIT_LENGTH, iv);
        return Encoder.encodeHex(iv) + Encoder.encodeHex(aesCipher.encrypt(plainText, secretKey, parameterSpec));
    }

    @Override
    public String decrypt(String cipherText) {
        byte[] iv = extractIv(cipherText);
        if (iv == null) {
            return null;
        }
        AesCipher aesCipher = aesCipherFactory.get();
        var parameterSpec = new GCMParameterSpec(GCM_BIT_LENGTH, iv);
        byte[] cipherBytes = Encoder.decodeHex(cipherText.substring(GCM_IV_LENGTH * 2));
        return aesCipher.decrypt(cipherBytes, secretKey, parameterSpec);
    }

    private byte[] extractIv(String cipherText) {
        try {
            return Encoder.decodeHex(cipherText.substring(0, GCM_IV_LENGTH * 2));
        } catch (Exception e) {
            return null;
        }
    }
}
