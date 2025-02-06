package org.example.encrypt.encryptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.example.encrypt.cipher.SimpleAesCipherFactory;
import org.junit.jupiter.api.Test;

class DelegatingAesEncryptorTest {

    private static final String PLAIN_TEXT = "HELLO";

    @Test
    void delegating() {
        // given
        AesEncryptor ecbEncryptor = new EcbAesEncryptor("1234567890", SimpleAesCipherFactory::new);
        AesEncryptor cbcEncryptor = new CbcAesEncryptor("1234567890", SimpleAesCipherFactory::new);
        AesEncryptor gcmEncryptor = new GcmAesEncryptor("1234567890", SimpleAesCipherFactory::new);
        AesEncryptor delegatingEncryptor = new DelegatingAesEncryptor("gcm", Map.of(
            "ecb", ecbEncryptor,
            "cbc", cbcEncryptor,
            "gcm", gcmEncryptor
        ), ecbEncryptor);

        // when
        String oldEncrypted = ecbEncryptor.encrypt(PLAIN_TEXT);
        String cbcEncrypted = "{cbc}" + cbcEncryptor.encrypt(PLAIN_TEXT);
        String gcmEncrypted = delegatingEncryptor.encrypt(PLAIN_TEXT);

        // then
        assertEquals(PLAIN_TEXT, delegatingEncryptor.decrypt(oldEncrypted));
        assertEquals(PLAIN_TEXT, delegatingEncryptor.decrypt(cbcEncrypted));
        assertEquals(PLAIN_TEXT, delegatingEncryptor.decrypt(gcmEncrypted));
        assertTrue(gcmEncrypted.startsWith("{gcm}"));
    }
}
