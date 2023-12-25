package org.example;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * @see <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf">Secure org.example.Hash Standard</a>
 */
public class SHA1 implements Hash {
    public static final int WORD_SIZE_IN_BITS = 32;
    public static final int BLOCK_SIZE_IN_BITS = 512;
    public static final int DIGEST_SIZE_IN_BITS = 160;

    @Override
    public byte[] getDigest(byte[] message) {
        if (message.length == 0) {
            return new byte[0];
        }

        byte[][] M = splitIntoBlocks(addPadding(message));
        int[] H = new int[] { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };

        for (byte[] block : M) {
            int[] W = new int[80];

            // Prepare the message schedule
            int[] words = splitIntoWords(block);
            System.arraycopy(words, 0, W, 0, words.length);
            for (int t = words.length; t < W.length; ++t) {
                W[t] = rotateLeft(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
            }

            // Initialize working variables
            int a = H[0];
            int b = H[1];
            int c = H[2];
            int d = H[3];
            int e = H[4];

            for (int t = 0; t < W.length; ++t) {
                int F, K;
                if (t <= 19) {
                    F = F0(b, c, d);
                    K = 0x5a827999;
                } else if (t <= 39) {
                    F = F1(b, c, d);
                    K = 0x6ed9eba1;
                } else if (t <= 59) {
                    F = F2(b, c, d);
                    K = 0x8f1bbcdc;
                } else {
                    F = F1(b, c, d);
                    K = 0xca62c1d6;
                }

                int T = rotateLeft(a, 5) + F + e + K + W[t];
                e = d;
                d = c;
                c = rotateLeft(b, 30);
                b = a;
                a = T;
            }

            // Compute the final result
            H[0] += a;
            H[1] += b;
            H[2] += c;
            H[3] += d;
            H[4] += e;
        }

        return splitIntoBytes(new int[] { H[0], H[1], H[2], H[3], H[4] });
    }

    public byte[] addPadding(byte[] message) {
        if (message.length == 0) {
            return new byte[0];
        }

        // Calculate the size of the padded message
        int outputSize = 0;
        while (outputSize <= message.length + (2* WORD_SIZE_IN_BITS / Byte.SIZE) + 1) {
            outputSize += BLOCK_SIZE_IN_BITS / Byte.SIZE;
        }

        byte[] padded = Arrays.copyOf(message, outputSize);

        // Append the bit "1" at the end of the input message
        padded[message.length] = (byte) (1 << 7);

        // Set the last two words to the size of the input message
        byte[] tmp = new BigInteger(String.valueOf(message.length*Byte.SIZE)).toByteArray();
        for (int i = 1; i <= tmp.length; ++i) {
            padded[padded.length - i] = tmp[tmp.length - i];
        }

        return padded;
    }

    public byte[][] splitIntoBlocks(byte[] message) throws RuntimeException {
        if (message.length % (BLOCK_SIZE_IN_BITS / Byte.SIZE) != 0) {
            throw new RuntimeException("Message is not padded");
        }

        byte[][] blocks = new byte[message.length / (BLOCK_SIZE_IN_BITS / Byte.SIZE)][];
        for (int i = 0, j = 0; i < message.length; i += (BLOCK_SIZE_IN_BITS / Byte.SIZE), ++j) {
            blocks[j] = Arrays.copyOfRange(message, i, i + (BLOCK_SIZE_IN_BITS / Byte.SIZE));
        }

        return blocks;
    }

    public int[] splitIntoWords(byte[] block) throws RuntimeException {
        if (block.length % (WORD_SIZE_IN_BITS / Byte.SIZE) != 0) {
            throw new RuntimeException("Block size is not a multiple of the word size");
        }

        int[] words = new int[(block.length * Byte.SIZE) / WORD_SIZE_IN_BITS];
        for (int i = 0; i < words.length; ++i) {
            words[i] = ByteBuffer.wrap(new byte[] {
                    block[4*i], block[4*i + 1], block[4*i + 2], block[4*i + 3]
            }).getInt();
        }

        return words;
    }

    public byte[] splitIntoBytes(int[] words) {
        if (words.length == 0) {
            return new byte[0];
        }
3
        byte[] bytes = new byte[words.length*(WORD_SIZE_IN_BITS / Byte.SIZE)];
        for (int i = 0; i < words.length; ++i) {
            bytes[4*i] = (byte)(words[i] >>> 24);
            bytes[4*i + 1] = (byte)(words[i] >>> 16);
            bytes[4*i + 2] = (byte)(words[i] >>> 8);
            bytes[4*i + 3] = (byte)(words[i]);
        }

        return bytes;
    }

    private int F0(int x, int y, int z) {
        return (x & y) ^ ((~x) & z);
    }

    private int F1(int x, int y, int z) {
        return x ^ y ^ z;
    }

    private int F2(int x, int y, int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private int rotateLeft(int word, int bits) {
        return ((word << bits) | (word >>> (WORD_SIZE_IN_BITS - bits)));
    }
}
