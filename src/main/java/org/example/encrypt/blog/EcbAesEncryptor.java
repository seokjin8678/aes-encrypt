package org.example.encrypt.blog;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.apache.commons.codec.binary.Hex;

public class EcbAesEncryptor extends AesEncryptHelper implements AesEncryptor {

    private final SecretKey secretKey;
    private final CipherPool cipherPool;

    public EcbAesEncryptor(SecretKey secretKey) {
        this.secretKey = secretKey;
        cipherPool = new CipherPool("AES/ECB/PKCS5Padding");
    }

    @Override
    public String encrypt(String plainText) throws Exception {
        Cipher cipher = null;
        try {
            cipher = cipherPool.borrowCipher();
            return Hex.encodeHexString(encrypt(cipher, plainText, secretKey, null));
        } finally {
            cipherPool.returnCipher(cipher);
        }
    }

    @Override
    public String decrypt(String cipherText) throws Exception {
        Cipher cipher = null;
        try {
            cipher = cipherPool.borrowCipher();
            return decrypt(cipher, Hex.decodeHex(cipherText), secretKey, null);
        } finally {
            cipherPool.returnCipher(cipher);
        }
    }
}
