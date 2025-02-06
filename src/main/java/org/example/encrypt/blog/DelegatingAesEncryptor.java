package org.example.encrypt.blog;

import java.util.Map;

public class DelegatingAesEncryptor implements AesEncryptor {

    private static final String PREFIX = "{";
    private static final String SUFFIX = "}";
    private final String idToEncrypt;
    private final Map<String, AesEncryptor> idToEncryptor;
    private final AesEncryptor defaultEncryptor;
    private final AesEncryptor fallback;

    public DelegatingAesEncryptor(String idToEncrypt, Map<String, AesEncryptor> idToEncryptor, AesEncryptor fallback) {
        this.idToEncrypt = idToEncrypt;
        this.idToEncryptor = idToEncryptor;
        this.fallback = fallback;
        this.defaultEncryptor = idToEncryptor.get(idToEncrypt);
    }

    @Override
    public String encrypt(String plainText) throws Exception {
        if (plainText == null) {
            return null;
        }
        return PREFIX + idToEncrypt + SUFFIX + defaultEncryptor.encrypt(plainText);
    }

    @Override
    public String decrypt(String cipherText) throws Exception {
        String id = extractId(cipherText);
        if (id == null) {
            return fallback.decrypt(cipherText);
        }
        AesEncryptor encryptor = idToEncryptor.get(id);
        if (encryptor == null) {
            return fallback.decrypt(cipherText);
        }
        return encryptor.decrypt(extractCipherText(cipherText));
    }

    private String extractId(String cipherText) {
        if (cipherText == null) {
            return null;
        }
        int start = cipherText.indexOf(PREFIX);
        if (start != 0) {
            return null;
        }
        int end = cipherText.indexOf(SUFFIX, start);
        if (end < 0) {
            return null;
        }
        return cipherText.substring(start + PREFIX.length(), end);
    }

    private String extractCipherText(String cipherText) {
        int start = cipherText.indexOf(SUFFIX);
        return cipherText.substring(start + SUFFIX.length());
    }
}
