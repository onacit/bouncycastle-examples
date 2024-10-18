package com.github.onacit.examples;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

public final class BufferedBlockCipherUtils {

    public static byte[] processBytes(final BufferedBlockCipher cipher, final InputStream source,
                                      final OutputStream target, final int length)
            throws IOException, InvalidCipherTextException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (length <= 0) {
            throw new IllegalArgumentException("non-positive length: " + length);
        }
        final var in = new byte[length];
        var out = new byte[in.length];
        for (int r; (r = source.read(in)) != -1; ) {
            final var outputSize = cipher.getOutputSize(r);
            if (out.length < outputSize) {
                out = new byte[outputSize];
            }
            target.write(out, 0, cipher.processBytes(in, 0, r, out, 0));
        }
        Arrays.clear(out);
        return out;
    }

    public static void processBytesAndDoFinal(final BufferedBlockCipher cipher, final InputStream source,
                                              final OutputStream target, final int length)
            throws IOException, InvalidCipherTextException {
        if (true) {
            final var out = processBytes(cipher, source, target, length);
            target.write(out, 0, cipher.doFinal(out, 0));
            return;
        }
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (length <= 0) {
            throw new IllegalArgumentException("non-positive length: " + length);
        }
        final var in = new byte[length];
        var out = new byte[in.length];
        for (int r; (r = source.read(in)) != -1; ) {
            final var outputSize = cipher.getOutputSize(r);
            if (out.length < outputSize) {
                out = new byte[outputSize];
            }
            target.write(out, 0, cipher.processBytes(in, 0, r, out, 0));
        }
        target.write(out, 0, cipher.doFinal(out, 0));
    }

    private BufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
