package org.example;

import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import org.example.encrypt.cipher.ObjectPoolAesCipherFactory;
import org.example.encrypt.cipher.SimpleAesCipherFactory;
import org.example.encrypt.encryptor.AesEncryptor;
import org.example.encrypt.encryptor.EcbAesEncryptor;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.infra.Blackhole;

@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
@State(Scope.Benchmark)
public class EcbAesEncryptBenchMark {

    private static final int TEXT_SIZE = 100;

    AesEncryptor simpleAesEncryptor;
    AesEncryptor objectPoolAesEncryptor;
    List<String> plainTexts;
    List<String> encryptedTexts;

    @Setup(Level.Trial)
    public void setup() {
        simpleAesEncryptor = new EcbAesEncryptor("1234567890", SimpleAesCipherFactory::new);
        objectPoolAesEncryptor = new EcbAesEncryptor("1234567890", ObjectPoolAesCipherFactory::new);
        plainTexts = ThreadLocalRandom.current().ints(TEXT_SIZE)
            .mapToObj(String::valueOf)
            .toList();
        encryptedTexts = plainTexts.stream()
            .map(objectPoolAesEncryptor::encrypt)
            .toList();
    }

    @TearDown(Level.Trial)
    public void teardown() {
        System.gc();
    }

    @Benchmark
    public void encryptWithSimple(Blackhole bh) {
        String plainText = plainTexts.get(ThreadLocalRandom.current().nextInt(TEXT_SIZE));
        bh.consume(simpleAesEncryptor.encrypt(plainText));
    }

    @Benchmark
    public void decryptWithSimple(Blackhole bh) {
        String encryptedText = encryptedTexts.get(ThreadLocalRandom.current().nextInt(TEXT_SIZE));
        bh.consume(simpleAesEncryptor.decrypt(encryptedText));
    }

    @Benchmark
    public void encryptWithObjectPool(Blackhole bh) {
        String plainText = plainTexts.get(ThreadLocalRandom.current().nextInt(TEXT_SIZE));
        bh.consume(objectPoolAesEncryptor.encrypt(plainText));
    }

    @Benchmark
    public void decryptWithObjectPool(Blackhole bh) {
        String encryptedText = encryptedTexts.get(ThreadLocalRandom.current().nextInt(TEXT_SIZE));
        bh.consume(objectPoolAesEncryptor.decrypt(encryptedText));
    }
}
