package org.example.encrypt.encryptor;

public enum AesBit {
    BIT128(16),
    BIT192(24),
    BIT256(32),
    ;

    private final int byteLength;

    AesBit(int byteLength) {
        this.byteLength = byteLength;
    }

    public int getByteLength() {
        return byteLength;
    }
}
