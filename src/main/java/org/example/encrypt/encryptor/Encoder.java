package org.example.encrypt.encryptor;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class Encoder {

    public static String encodeHex(byte[] date) {
        return Hex.encodeHexString(date);
    }

    public static String encodeBase64(byte[] date) {
        return Base64.encodeBase64String(date);
    }

    public static byte[] decodeHex(String date) {
        try {
            return Hex.decodeHex(date);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static byte[] decodeBase64(String date) {
        return Base64.decodeBase64(date);
    }
}
