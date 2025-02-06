package org.example.encrypt.blog;

public interface AesEncryptor {

    String encrypt(String plainText) throws Exception;

    String decrypt(String cipherText) throws Exception;
}
