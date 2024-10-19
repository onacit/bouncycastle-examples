package com.github.onacit.examples;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.util.Arrays;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

public final class BufferedBlockCipherUtils {

    /**
     * Process, using specified cipher, all bytes from specified input stream, and write processed bytes to specified
     * output stream.
     *
     * @param cipher the cipher.
     * @param source the input stream from which bytes to process are read.
     * @param target the output stream to which processed bytes are written.
     * @param in     a buffer for reading bytes from {@code source}.
     * @return an array of bytes suitable for the {@code out} of
     * {@link BufferedBlockCipher#doFinal(byte[], int) doFinal}.
     * @throws IOException if an I/O error occurs.
     * @see BufferedBlockCipher#processBytes(byte[], int, int, byte[], int)
     * @see <a
     * href="https://downloads.bouncycastle.org/java/docs/bcprov-jdk18on-javadoc/org/bouncycastle/crypto/BufferedBlockCipher.html">org.bouncycastle.crypto.BufferedBlockCipher</a>
     * (bcprov-jdk18on-javadoc)
     */
    public static byte[] processBytes(final BufferedBlockCipher cipher, final InputStream source,
                                      final OutputStream target, final byte[] in)
            throws IOException {
        Objects.requireNonNull(cipher, "cipher is null");
        Objects.requireNonNull(source, "source is null");
        Objects.requireNonNull(target, "target is null");
        if (Objects.requireNonNull(in, "in is null").length <= 0) {
            throw new IllegalArgumentException("in.length is zero");
        }
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
                                              final OutputStream target, final byte[] in)
            throws IOException, InvalidCipherTextException {
        final var out = processBytes(cipher, source, target, in);
        target.write(out, 0, cipher.doFinal(out, 0));
    }

    private BufferedBlockCipherUtils() {
        throw new AssertionError("instantiation is not allowed");
    }
}
