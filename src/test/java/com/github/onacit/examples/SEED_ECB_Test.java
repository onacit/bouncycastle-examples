package com.github.onacit.examples;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DefaultBufferedBlockCipher;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
class SEED_ECB_Test {

    private static Stream<Arguments> getArgumentsStream() {
        final var engine = new SEEDEngine();
        log.debug("algorithmName: {}, blockSize: {}", engine.getAlgorithmName(), engine.getBlockSize());
//            final var cipher = new PaddedBufferedBlockCipher(new DefaultBufferedBlockCipher(engine), p);
        final var cipher = new DefaultBufferedBlockCipher(engine);
        final CipherParameters params;
        final byte[] key;
        {
            key = new byte[engine.getBlockSize()];
            ThreadLocalRandom.current().nextBytes(key);
        }
        params = new KeyParameter(key);
        return Stream.of(Arguments.of(
                cipher,
                Named.of(String.format("key: %1$02x...", key[0]), params)
        ));
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params) throws Exception {
        // ------------------------------------------------------------------------------------------------------- plain
        final byte[] plain;
        {
            plain = new byte[cipher.getBlockSize() << ThreadLocalRandom.current().nextInt(3)];
            ThreadLocalRandom.current().nextBytes(plain);
        }
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = new byte[cipher.getOutputSize(plain.length)];
        {
            final var processed = cipher.processBytes(plain, 0, plain.length, encrypted, 0);
            final var finalized = cipher.doFinal(encrypted, processed);
            assertThat(processed + finalized).isEqualTo(encrypted.length);
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = new byte[cipher.getOutputSize(encrypted.length)];
        {
            final var processed = cipher.processBytes(encrypted, 0, encrypted.length, decrypted, 0);
            final var finalized = cipher.doFinal(decrypted, processed);
            final var length = processed + finalized;
            assertThat(length).isLessThanOrEqualTo(decrypted.length);
            assertThat(Arrays.copyOf(decrypted, length)).isEqualTo(plain);
        }
    }

    @MethodSource({"getArgumentsStream"})
    @ParameterizedTest
    void __(final BufferedBlockCipher cipher, final CipherParameters params, @TempDir final File dir)
            throws Exception {
        // ------------------------------------------------------------------------------------------------------- plain
        final var plain = File.createTempFile("tmp", null, dir);
        try (var stream = new FileOutputStream(plain)) {
            final var b = new byte[cipher.getBlockSize() << ThreadLocalRandom.current().nextInt(3)];
            ThreadLocalRandom.current().nextBytes(b);
            stream.write(b);
            stream.flush();
        }
        // ----------------------------------------------------------------------------------------------------- encrypt
        cipher.init(true, params);
        final var encrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(plain);
             var target = new FileOutputStream(encrypted)) {
            final var in = new byte[ThreadLocalRandom.current().nextInt(2, cipher.getBlockSize() << 1)];
            var out = new byte[cipher.getOutputSize(in.length)];
            for (int inLen; (inLen = source.read(in)) != -1; ) {
                final var outputSize = cipher.getOutputSize(inLen);
                if (out.length < outputSize) {
                    out = new byte[out.length << 1];
                }
                final var outLen = cipher.processBytes(in, 0, inLen, out, 0);
                target.write(out, 0, outLen);
            }
            target.write(out, 0, cipher.doFinal(out, 0));
            target.flush();
        }
        // ----------------------------------------------------------------------------------------------------- decrypt
        cipher.init(false, params);
        final var decrypted = File.createTempFile("tmp", null, dir);
        try (var source = new FileInputStream(encrypted);
             var target = new FileOutputStream(decrypted)) {
            final var in = new byte[ThreadLocalRandom.current().nextInt(2, cipher.getBlockSize() << 1)];
            var out = new byte[cipher.getOutputSize(in.length)];
            for (int inLen; (inLen = source.read(in)) != -1; ) {
                final var outputSize = cipher.getOutputSize(inLen);
                if (out.length < outputSize) {
                    out = new byte[out.length << 1];
                }
                final var outLen = cipher.processBytes(in, 0, inLen, out, 0);
                target.write(out, 0, outLen);
            }
            target.write(out, 0, cipher.doFinal(out, 0));
            target.flush();
        }
        // -------------------------------------------------------------------------------------------------------- then
        assertThat(decrypted).hasSize(plain.length());
        for (var algorithm : new String[]{"SHA-1", "SHA-256"}) {
            final var digest = MessageDigest.getInstance(algorithm);
            assertThat(decrypted).hasDigest(digest, DigestUtils.digest(digest, plain));
        }
    }
}
