package org.example.encrypt.encryptor;

import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SecretKeyUtil {

    private SecretKeyUtil() {
        throw new UnsupportedOperationException();
    }

    public static SecretKey createAes(String secretKey, AesBit aesBit) {
        if (secretKey == null || secretKey.isBlank()) {
            throw new IllegalArgumentException();
        }
        int aesByteLength = aesBit.getByteLength();
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length > aesByteLength) {
            byte[] newKey = new byte[aesByteLength];
            System.arraycopy(keyBytes, 0, newKey, 0, aesByteLength);
            int idx = 0;
            for (int i = aesByteLength; i < keyBytes.length; i++) {
                newKey[idx] = (byte) (newKey[idx] ^ keyBytes[i]);
                idx++;
                if (idx >= aesByteLength) {
                    idx = 0;
                }
            }
            keyBytes = newKey;
        } else if (keyBytes.length < aesByteLength) {
            byte[] newKey = new byte[aesByteLength];
            System.arraycopy(keyBytes, 0, newKey, 0, keyBytes.length);
            for (int i = keyBytes.length; i < newKey.length; i++) {
                newKey[i] = 0;
            }
            keyBytes = newKey;
        }
        return new SecretKeySpec(keyBytes, "AES");
    }
}
