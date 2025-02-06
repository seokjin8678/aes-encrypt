package org.example.encrypt.blog;

import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.apache.commons.codec.binary.Hex;

public class GcmAesEncryptor extends AesEncryptHelper implements AesEncryptor {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_BIT_LENGTH = 128;

    private final SecretKey secretKey;
    private final CipherPool cipherPool;

    public GcmAesEncryptor(SecretKey secretKey) {
        this.secretKey = secretKey;
        this.cipherPool = new CipherPool("AES/GCM/NoPadding");
    }

    @Override
    public String encrypt(String plainText) throws Exception {
        Cipher cipher = null;
        try {
            cipher = cipherPool.borrowCipher();
            byte[] iv = new byte[GCM_IV_LENGTH];
            ThreadLocalRandom.current().nextBytes(iv);
            byte[] encrypted = encrypt(cipher, plainText, secretKey, new GCMParameterSpec(GCM_BIT_LENGTH, iv));
            return Hex.encodeHexString(iv) + Hex.encodeHexString(encrypted);
        } finally {
            cipherPool.returnCipher(cipher);
        }
    }

    @Override
    public String decrypt(String cipherText) throws Exception {
        Cipher cipher = null;
        try {
            cipher = cipherPool.borrowCipher();
            byte[] iv = Hex.decodeHex(cipherText.substring(0, GCM_IV_LENGTH * 2));
            byte[] decodedCipher = Hex.decodeHex(cipherText.substring(GCM_IV_LENGTH * 2));
            return decrypt(cipher, decodedCipher, secretKey, new GCMParameterSpec(GCM_BIT_LENGTH, iv));
        } finally {
            cipherPool.returnCipher(cipher);
        }
    }
}
