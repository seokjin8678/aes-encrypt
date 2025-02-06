package org.example.encrypt.blog;

import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.codec.binary.Hex;

public class CbcAesEncryptor extends AesEncryptHelper implements AesEncryptor {

    private static final int IV_LENGTH = 16;

    private final SecretKey secretKey;
//    private final CipherPool cipherPool;

    public CbcAesEncryptor(SecretKey secretKey) {
        this.secretKey = secretKey;
//        this.cipherPool = new CipherPool("AES/CBC/PKCS5Padding");
    }

    @Override
    public String encrypt(String plainText) throws Exception {
//        Cipher cipher = null;
//        try {
//            cipher = cipherPool.borrowCipher();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[IV_LENGTH];
        ThreadLocalRandom.current().nextBytes(iv);
        byte[] encrypted = encrypt(cipher, plainText, secretKey, new IvParameterSpec(iv));
        return Hex.encodeHexString(iv) + Hex.encodeHexString(encrypted);
//        } finally {
//            cipherPool.returnCipher(cipher);
//        }
    }

    @Override
    public String decrypt(String cipherText) throws Exception {
//        Cipher cipher = null;
//        try {
//            cipher = cipherPool.borrowCipher();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = Hex.decodeHex(cipherText.substring(0, IV_LENGTH * 2));
        byte[] decodedCipher = Hex.decodeHex(cipherText.substring(IV_LENGTH * 2));
        return decrypt(cipher, decodedCipher, secretKey, new IvParameterSpec(iv));
//        } finally {
//            cipherPool.returnCipher(cipher);
//        }
    }
}
