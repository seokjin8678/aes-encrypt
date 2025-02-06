package org.example.encrypt.encryptor;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.example.encrypt.cipher.SimpleAesCipherFactory;
import org.junit.jupiter.api.Test;

class GcmAesEncryptorTest {

    private static final String PLAIN_TEXT = "HELLO";

    @Test
    void encryptAndDecrypt() {
        // given
        AesEncryptor aesEncryptor = new GcmAesEncryptor("1234567890", SimpleAesCipherFactory::new);

        // when
        String encrypted = aesEncryptor.encrypt(PLAIN_TEXT);
        String decrypted = aesEncryptor.decrypt(encrypted);

        // then
        assertEquals(PLAIN_TEXT, decrypted);
    }
}
