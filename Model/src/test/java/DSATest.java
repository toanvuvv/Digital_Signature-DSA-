import org.example.DSA;
import org.example.SHA1;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

public class DSATest {
    private DSA dsa;
    private byte[] p;
    private byte[] q;
    private byte[] g;
    private byte[] x;
    private byte[] y;

    private final int L = 1024;
    private final int N = 160;

    private byte[] message;

    @BeforeEach
    void setUp() {
        dsa = new DSA(new SHA1());
        p = new byte[] {
                (byte) 0x97, (byte) 0xd8, (byte) 0x3f, (byte) 0x3f, (byte) 0x5b, (byte) 0x5a, (byte) 0x13, (byte) 0xb7,
                (byte) 0x47, (byte) 0x93, (byte) 0x74, (byte) 0x18, (byte) 0x59, (byte) 0xe2, (byte) 0xea, (byte) 0x97,
                (byte) 0x06, (byte) 0xf9, (byte) 0x0f, (byte) 0x67, (byte) 0x02, (byte) 0x12, (byte) 0x57, (byte) 0x05,
                (byte) 0xb5, (byte) 0x2a, (byte) 0xb8, (byte) 0x9f, (byte) 0x81, (byte) 0x95, (byte) 0x6c, (byte) 0x1b,
                (byte) 0x86, (byte) 0xaf, (byte) 0x52, (byte) 0x5d, (byte) 0xf7, (byte) 0x4f, (byte) 0xb5, (byte) 0x33,
                (byte) 0x6a, (byte) 0x5a, (byte) 0x65, (byte) 0xae, (byte) 0x5c, (byte) 0xea, (byte) 0xba, (byte) 0x16,
                (byte) 0xa8, (byte) 0x02, (byte) 0xad, (byte) 0x83, (byte) 0x9a, (byte) 0x7c, (byte) 0x0c, (byte) 0x8f,
                (byte) 0x5d, (byte) 0x9b, (byte) 0x0e, (byte) 0xf0, (byte) 0xbd, (byte) 0xf9, (byte) 0xc3, (byte) 0x93,
                (byte) 0xbd, (byte) 0x5b, (byte) 0x48, (byte) 0x03, (byte) 0x84, (byte) 0x51, (byte) 0x0f, (byte) 0x6f,
                (byte) 0x0b, (byte) 0xf5, (byte) 0xf0, (byte) 0xc4, (byte) 0x46, (byte) 0xd3, (byte) 0xb3, (byte) 0xb8,
                (byte) 0xe4, (byte) 0xca, (byte) 0xe6, (byte) 0x99, (byte) 0xb9, (byte) 0x65, (byte) 0xfd, (byte) 0x9e,
                (byte) 0x2c, (byte) 0x4c, (byte) 0x20, (byte) 0xd2, (byte) 0x18, (byte) 0x9d, (byte) 0xb3, (byte) 0x72,
                (byte) 0x1b, (byte) 0xcf, (byte) 0x39, (byte) 0xbd, (byte) 0x9b, (byte) 0xfd, (byte) 0x52, (byte) 0x63,
                (byte) 0x74, (byte) 0x4c, (byte) 0x6a, (byte) 0xa6, (byte) 0xe6, (byte) 0x99, (byte) 0x2e, (byte) 0x37,
                (byte) 0x4f, (byte) 0x7e, (byte) 0xc7, (byte) 0x96, (byte) 0x1e, (byte) 0x81, (byte) 0xcd, (byte) 0x39,
                (byte) 0xdb, (byte) 0xcd, (byte) 0x8f, (byte) 0x80, (byte) 0xa6, (byte) 0x80, (byte) 0x2b, (byte) 0x8f
        };
        q = new byte[] {
                (byte) 0xff, (byte) 0x27, (byte) 0xf2, (byte) 0x60, (byte) 0x73, (byte) 0x6a, (byte) 0x34, (byte) 0x5e,
                (byte) 0xab, (byte) 0xad, (byte) 0x03, (byte) 0x62, (byte) 0xab, (byte) 0xc0, (byte) 0xe0, (byte) 0x00,
                (byte) 0xae, (byte) 0xdf, (byte) 0xe0, (byte) 0x61
        };
        g = new byte[] {
                (byte) 0x46, (byte) 0xaa, (byte) 0xe8, (byte) 0x30, (byte) 0xbf, (byte) 0x23, (byte) 0x6b, (byte) 0x60,
                (byte) 0x45, (byte) 0x9d, (byte) 0x11, (byte) 0x8e, (byte) 0xc7, (byte) 0x46, (byte) 0x51, (byte) 0x25,
                (byte) 0x94, (byte) 0xb6, (byte) 0x89, (byte) 0x38, (byte) 0x2c, (byte) 0xea, (byte) 0xe6, (byte) 0x52,
                (byte) 0x3b, (byte) 0xba, (byte) 0x74, (byte) 0x4a, (byte) 0x39, (byte) 0x53, (byte) 0x84, (byte) 0xf1,
                (byte) 0x05, (byte) 0x57, (byte) 0x79, (byte) 0x55, (byte) 0xb0, (byte) 0x56, (byte) 0xbe, (byte) 0xed,
                (byte) 0x04, (byte) 0x11, (byte) 0x63, (byte) 0x62, (byte) 0xee, (byte) 0xa9, (byte) 0xd9, (byte) 0x75,
                (byte) 0xe1, (byte) 0x7a, (byte) 0x88, (byte) 0xce, (byte) 0x4f, (byte) 0xf0, (byte) 0x9e, (byte) 0xd4,
                (byte) 0xb4, (byte) 0xe7, (byte) 0x32, (byte) 0x75, (byte) 0x24, (byte) 0xc2, (byte) 0x29, (byte) 0xb8,
                (byte) 0xee, (byte) 0x9b, (byte) 0x68, (byte) 0xca, (byte) 0x83, (byte) 0xb7, (byte) 0xe8, (byte) 0x08,
                (byte) 0x90, (byte) 0x25, (byte) 0xc5, (byte) 0x3a, (byte) 0x0b, (byte) 0x18, (byte) 0xc0, (byte) 0x5b,
                (byte) 0xbe, (byte) 0x30, (byte) 0x1a, (byte) 0x2a, (byte) 0x64, (byte) 0xe8, (byte) 0x75, (byte) 0xe6,
                (byte) 0x87, (byte) 0x94, (byte) 0x63, (byte) 0x08, (byte) 0xbe, (byte) 0xfc, (byte) 0xfb, (byte) 0x10,
                (byte) 0x0f, (byte) 0x8a, (byte) 0xe2, (byte) 0x2a, (byte) 0x48, (byte) 0x07, (byte) 0xca, (byte) 0xc1,
                (byte) 0xb7, (byte) 0x8a, (byte) 0x56, (byte) 0xad, (byte) 0xf8, (byte) 0x26, (byte) 0xb2, (byte) 0xd7,
                (byte) 0x6c, (byte) 0x4d, (byte) 0xd4, (byte) 0xbf, (byte) 0xa1, (byte) 0xf9, (byte) 0xaf, (byte) 0x27,
                (byte) 0x62, (byte) 0xce, (byte) 0x5e, (byte) 0x56, (byte) 0x02, (byte) 0x35, (byte) 0x67, (byte) 0x62
        };
        x = new byte[] {
                (byte) 0x8f, (byte) 0xb8, (byte) 0xdd, (byte) 0x2b, (byte) 0xfc, (byte) 0x11, (byte) 0x0c, (byte) 0x34,
                (byte) 0x2a, (byte) 0x7a, (byte) 0x22, (byte) 0xd4, (byte) 0xc1, (byte) 0x9f, (byte) 0xc8, (byte) 0x1f,
                (byte) 0x7a, (byte) 0xb2, (byte) 0x34, (byte) 0xf7
        };
        y = new byte[] {
                (byte) 0x3a, (byte) 0x5c, (byte) 0xc0, (byte) 0x02, (byte) 0x2c, (byte) 0x6c, (byte) 0x64, (byte) 0x22,
                (byte) 0xf1, (byte) 0xdb, (byte) 0x97, (byte) 0xca, (byte) 0x32, (byte) 0x5b, (byte) 0xf0, (byte) 0x4b,
                (byte) 0x51, (byte) 0x88, (byte) 0xea, (byte) 0x54, (byte) 0x94, (byte) 0xe5, (byte) 0x2a, (byte) 0x7a,
                (byte) 0x9c, (byte) 0x4f, (byte) 0x50, (byte) 0x9b, (byte) 0x60, (byte) 0x1a, (byte) 0x42, (byte) 0xd4,
                (byte) 0x52, (byte) 0xdf, (byte) 0xa1, (byte) 0xa1, (byte) 0x3e, (byte) 0x99, (byte) 0x36, (byte) 0x22,
                (byte) 0x20, (byte) 0xc9, (byte) 0xe3, (byte) 0x84, (byte) 0xae, (byte) 0xcc, (byte) 0x28, (byte) 0x6a,
                (byte) 0x5a, (byte) 0x32, (byte) 0x5a, (byte) 0xac, (byte) 0xdc, (byte) 0x71, (byte) 0xfd, (byte) 0xf3,
                (byte) 0xdd, (byte) 0x5c, (byte) 0x63, (byte) 0x65, (byte) 0xfa, (byte) 0xe4, (byte) 0x67, (byte) 0x12,
                (byte) 0x12, (byte) 0x45, (byte) 0x29, (byte) 0x0b, (byte) 0xa6, (byte) 0xc1, (byte) 0x2d, (byte) 0x73,
                (byte) 0x05, (byte) 0x01, (byte) 0x61, (byte) 0x88, (byte) 0x19, (byte) 0xcf, (byte) 0x15, (byte) 0xbd,
                (byte) 0xa8, (byte) 0x10, (byte) 0xb2, (byte) 0x82, (byte) 0x6f, (byte) 0xe4, (byte) 0x67, (byte) 0xd0,
                (byte) 0xd4, (byte) 0x31, (byte) 0x02, (byte) 0x13, (byte) 0x04, (byte) 0x8d, (byte) 0x95, (byte) 0x99,
                (byte) 0xd8, (byte) 0x24, (byte) 0x07, (byte) 0x5c, (byte) 0x11, (byte) 0xbb, (byte) 0x32, (byte) 0x20,
                (byte) 0xd6, (byte) 0xfa, (byte) 0x02, (byte) 0x09, (byte) 0xed, (byte) 0x55, (byte) 0xdb, (byte) 0x0f,
                (byte) 0x0a, (byte) 0x4c, (byte) 0x80, (byte) 0x27, (byte) 0xb8, (byte) 0x69, (byte) 0xf7, (byte) 0xf5,
                (byte) 0x0b, (byte) 0xaa, (byte) 0x32, (byte) 0x68, (byte) 0x9b, (byte) 0x91, (byte) 0x17, (byte) 0x78
        };
        message = new byte[] {
                (byte) 0x46, (byte) 0x75, (byte) 0x63, (byte) 0x6b, (byte) 0x20, (byte) 0x4d, (byte) 0x61, (byte) 0x74,
                (byte) 0x65, (byte) 0x75, (byte) 0x73, (byte) 0x7a, (byte) 0x47, (byte) 0x32, (byte) 0x30, (byte) 0x30,
                (byte) 0x31
        };
    }

    @Test
    void TestGetPublicKeyIfKeyWasNotSetThenReturnsNull() {
        assertNull(dsa.getPublicKey());
    }

    @Test
    void TestGetPrivateKeyIfKeyWasNotSetThenReturnsNull() {
        assertNull(dsa.getPrivateKey());
    }

    @Test
    void TestSetKeysIfValidKeysThenSetsTheKeys() {
        dsa.setDomainParameters(p, q, g);
        dsa.setKeys(y, x);
        assertArrayEquals(y, dsa.getPublicKey());
        assertArrayEquals(x, dsa.getPrivateKey());
    }

    @Test
    void TestSetKeysIfParametersAreModifiedAfterCallThenTheKeysAreNotAltered() {
        byte[] tmpPublicKey = y.clone();
        byte[] tmpPrivateKey = x.clone();
        dsa.setDomainParameters(p, q, g);
        dsa.setKeys(tmpPublicKey, tmpPrivateKey);

        tmpPublicKey[0]--;
        tmpPrivateKey[0]--;

        assertArrayEquals(y, dsa.getPublicKey());
        assertArrayEquals(x, dsa.getPrivateKey());
    }

    @Test
    void TestSetKeysIfDomainParametersWereNotSetThenThrowsAnException() {
        assertThrows(Exception.class, () -> {
            dsa.setKeys(y, x);
        });
    }

    @Test
    void TestSetKeysIfKeysAreNotRelatedThenThrowsAnException() {
        g[0] = 0x02;
        dsa.setDomainParameters(p, q, g);
        assertThrows(Exception.class, () -> {
            dsa.setKeys(y, x);
        });
    }

    @Test
    void TestGetPIfPWasNotSetThenReturnsNull() {
        assertNull(dsa.getP());
    }

    @Test
    void TestGetQIfQWasNotSetThenReturnsNull() {
        assertNull(dsa.getQ());
    }

    @Test
    void TestGetGIfGWasNotSetThenReturnsNull() {
        assertNull(dsa.getG());
    }

    @Test
    void TestSetDomainParametersIfValidParametersThenSetsThem() {
        dsa.setDomainParameters(p.clone(), q.clone(), g.clone());
        byte[] ret = dsa.getP();
        assertArrayEquals(p, ret);
        assertArrayEquals(q, dsa.getQ());
        assertArrayEquals(g, dsa.getG());
    }

    @Test
    void TestSetDomainParametersIfQIsNotADivisorOfPMinusOneThenThrowsException()
    {
        assertThrows(Exception.class, () -> {
            dsa.setDomainParameters(p, new BigInteger(q).subtract(BigInteger.valueOf(1)).toByteArray(), g);
        });
    }

    @Test
    void TestSetDomainParametersIfPIsNotAPrimeThenThrowsException() {
        p = new byte[] {
                (byte) 0xdc, (byte) 0x1f, (byte) 0xbc, (byte) 0xb8, (byte) 0xbe, (byte) 0xd9, (byte) 0xcc, (byte) 0x26,
                (byte) 0x93, (byte) 0xd3, (byte) 0x76, (byte) 0x12, (byte) 0x0f, (byte) 0x57, (byte) 0x29, (byte) 0xb2,
                (byte) 0x33, (byte) 0x85, (byte) 0x04, (byte) 0xe4, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
        };
        q = new byte[] {
                (byte) 0xdc, (byte) 0x1f, (byte) 0xbc, (byte) 0xb8, (byte) 0xbe, (byte) 0xd9, (byte) 0xcc, (byte) 0x26,
                (byte) 0x93, (byte) 0xd3, (byte) 0x76, (byte) 0x12, (byte) 0x0f, (byte) 0x57, (byte) 0x29, (byte) 0xb2,
                (byte) 0x33, (byte) 0x85, (byte) 0x04, (byte) 0xe4
        };

        assertThrows(Exception.class, () -> {
            dsa.setDomainParameters(p, q, g);
        });
    }

    @Test
    void TestSetDomainParametersIfGIsLessThanTwoThenThrowsException() {
        assertThrows(Exception.class, () -> {
            dsa.setDomainParameters(p, q, new byte[] { 0x01 });
        });
    }

    @Test
    void TestSetDomainParametersIfGIsGreaterThanPThenThrowsException() {
        assertThrows(Exception.class, () -> {
            dsa.setDomainParameters(p, q, new BigInteger(p).add(BigInteger.ONE).toByteArray());
        });
    }

    @Test
    void TestGenerateKeysIfCalledThenDomainParametersAreSet() {
        dsa.generateKeys();
        assertNotNull(dsa.getP());
        assertNotNull(dsa.getQ());
        assertNotNull(dsa.getG());
    }

    @Test
    void TestGenerateKeysIfCalledThenKeysAreGenerated() {
        dsa.generateKeys();
        assertNotNull(dsa.getPublicKey());
        assertNotNull(dsa.getPrivateKey());
    }

    @Test
    void TestGenerateKeysIfCalledThenGeneratedPIsPrime() {
        dsa.generateKeys();
        assertTrue(new BigInteger(1, dsa.getP()).isProbablePrime(2));
    }

    @Test
    void TestGenerateKeysIfCalledThenGeneratedPIsInValidRange() {
        dsa.generateKeys();
        BigInteger pBig = new BigInteger(1, dsa.getP());
        assertTrue(pBig.compareTo(BigInteger.TWO.pow(L - 1)) > 0);
        assertTrue(pBig.compareTo(BigInteger.TWO.pow(L)) < 0);
    }

    @Test
    void TestGenerateKeysIfCalledThenGeneratedQIsInValidRange() {
        dsa.generateKeys();
        BigInteger qBig = new BigInteger(1, dsa.getQ());
        assertTrue(qBig.compareTo(BigInteger.TWO.pow(N - 1)) > 0);
        assertTrue(qBig.compareTo(BigInteger.TWO.pow(N)) < 0);
    }

    @Test
    void TestGenerateKeysIfCalledThenGeneratedQHasCorrectValueAccordingToP() {
        dsa.generateKeys();
        BigInteger pBig = new BigInteger(1, dsa.getP());
        BigInteger qBig = new BigInteger(1, dsa.getQ());
        assertEquals(0, pBig.subtract(BigInteger.ONE).mod(qBig).compareTo(BigInteger.ZERO));
    }

    @Test
    void TestGenerateKeysIfCalledThenGeneratedGIsInValidRange() {
        dsa.generateKeys();
        BigInteger pBig = new BigInteger(1, dsa.getP());
        BigInteger gBig = new BigInteger(1, dsa.getG());
        assertTrue(gBig.compareTo(BigInteger.ONE) > 0);
        assertTrue(gBig.compareTo(pBig) < 0);
    }

    @Test
    void TestGenerateKeysIfCalledThenGeneratedPrivateKeyIsInValidRange() {
        dsa.generateKeys();
        BigInteger xBig = new BigInteger(1, dsa.getPrivateKey());
        BigInteger qBig = new BigInteger(1, dsa.getQ());
        assertTrue(xBig.compareTo(BigInteger.ZERO) > 0);
        assertTrue(xBig.compareTo(qBig) < 0);
    }

    @Test
    void TestGenerateKeysIfCalledThenGeneratedPublicKeyHasCorrectValue() {
        dsa.generateKeys();
        BigInteger xBig = new BigInteger(1, dsa.getPrivateKey());
        BigInteger yBig = new BigInteger(1, dsa.getPublicKey());
        BigInteger pBig = new BigInteger(1, dsa.getP());
        BigInteger gBig = new BigInteger(1, dsa.getG());
        assertEquals(0, yBig.compareTo(gBig.modPow(xBig, pBig)));
    }

    @Test
    void TestSignIfDomainParametersAreNotSetThenThrowsException() {
        assertThrows(Exception.class, () -> {
            dsa.sign(new byte[] { 0x00, 0x01, 0x02 });
        });
    }

    @Test
    void TestSignIfKeysAreNotSetThenThrowsException() {
        dsa.setDomainParameters(p, q, g);
        assertThrows(Exception.class, () -> {
            dsa.sign(new byte[] { 0x00, 0x01, 0x02 });
        });
    }

    @Test
    void TestSignIfCalledProperlyThenReturnsValidValues() {
        dsa.setDomainParameters(p, q, g);
        dsa.setKeys(y, x);
        byte[][] sign = dsa.sign(new byte[] { 0x00, 0x01, 0x02 });
        assertNotEquals(new byte[] { 0x00 }, sign[0]);
        assertNotEquals(new byte[] { 0x00 }, sign[1]);
    }

    @Test
    void TestVerifyIfDomainsParametersAreNotSetThenThrowsException() {
        DSA tmp = new DSA(new SHA1());
        tmp.setDomainParameters(p, q, g);
        tmp.setKeys(y, x);
        byte[][] sign = tmp.sign(message);

        assertThrows(Exception.class, () -> {
            dsa.verify(message, sign);
        });
    }

    @Test
    void TestVerifyIfPublicKeyIsNotSetThenThrowsException() {
        DSA tmp = new DSA(new SHA1());
        tmp.setDomainParameters(p, q, g);
        tmp.setKeys(y, x);
        byte[][] sign = tmp.sign(message);

        dsa.setDomainParameters(p, q, g);
        assertThrows(Exception.class, () -> {
            dsa.verify(message, sign);
        });
    }

    @Test
    void TestVerifyIfRIsGreaterThanQThenReturnsFalse() {
        dsa.setDomainParameters(p, q, g);
        dsa.setKeys(y, x);
        byte[][] sign = dsa.sign(message);

        assertFalse(dsa.verify(message, new byte[][] {
                new BigInteger(q).add(BigInteger.ONE).toByteArray(),
                sign[1]
        }));
    }

    @Test
    void TestVerifyIfSIsGreaterThanQThenReturnsFalse() {
        dsa.setDomainParameters(p, q, g);
        dsa.setKeys(y, x);
        byte[][] sign = dsa.sign(message);

        assertFalse(dsa.verify(message, new byte[][] {
                sign[0],
                new BigInteger(q).add(BigInteger.ONE).toByteArray()
        }));
    }

    @Test
    void TestVerifyIfValidSignatureThenReturnsTrue() {
        dsa.setDomainParameters(p, q, g);
        dsa.setKeys(y, x);
        assertTrue(dsa.verify(message, dsa.sign(message)));
    }

    @Test
    void TestVerifyIfInvalidSignatureThenReturnsFalse() {
        dsa.setDomainParameters(p, q, g);
        dsa.setKeys(y, x);
        assertFalse(dsa.verify(message, dsa.sign(new byte[] { 0x02, 0x13, 0x37 })));
    }

    @Test
    void TestIsPrimeIfNegativeNumberThenReturnsFalse() {
        assertFalse(DSA.isPrime(BigInteger.ZERO.subtract(BigInteger.TWO), 2));
    }

    @Test
    void TestIsPrimeIfZeroOrOneOrFourThenReturnsFalse() {
        assertFalse(DSA.isPrime(BigInteger.ZERO, 2));
        assertFalse(DSA.isPrime(BigInteger.ONE, 2));
        assertFalse(DSA.isPrime(BigInteger.TWO.add(BigInteger.TWO), 2));
    }

    @Test
    void TestIsPrimeIfTwoOrThreeThenReturnsTrue() {
        assertTrue(DSA.isPrime(BigInteger.TWO, 2));
        assertTrue(DSA.isPrime(BigInteger.TWO.add(BigInteger.ONE), 2));
    }

    @Test
    void TestIsPrimeIfBigNonPrimeNumberThenReturnsFalse() {
        assertFalse(DSA.isPrime(new BigInteger("1446700333"), 2));
    }

    @Test
    void TestIsPrimeIfBigPrimeNumberThenReturnsTrue() {
        assertTrue(DSA.isPrime(new BigInteger("2147483647"), 2));
    }
}
