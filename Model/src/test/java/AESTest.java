import org.junit.jupiter.api.Assertions;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

public class AESTest {

    private final AES aes = new AES(new byte[]{0x2b, 0x7e, 0x15, 0x16, (byte) 0x28, (byte) 0xae, (byte) 0xd2, (byte) 0xa6,
            (byte) 0xab, (byte) 0xf7, 0x15, (byte) 0x88, 0x09, (byte) 0xcf, 0x4f, 0x3c});

    @Test
    void encryptDecryptTest() {
        byte[] plaintext = "Hello, world!".getBytes();
        byte[] ciphertext = aes.encrypt(plaintext);
        byte[] decryptedText = aes.decrypt(ciphertext);
        Assertions.assertArrayEquals(plaintext, decryptedText);
    }

    @Test
    void encryptDecryptTestForKeyLengthOf192Bits()
    {
        AES aes = new AES();
        aes.generateKey(AES.KEY_LENGTH.MEDIUM);
        byte[] plaintext = "Hello, world!".getBytes();
        byte[] ciphertext = aes.encrypt(plaintext);
        byte[] decryptedText = aes.decrypt(ciphertext);
        Assertions.assertArrayEquals(plaintext, decryptedText);
    }

    @Test
    void encryptDecryptTestForKeyLengthOf256Bits()
    {
        AES aes = new AES();
        aes.generateKey(AES.KEY_LENGTH.LONG);
        byte[] plaintext = "Hello, world!".getBytes();
        byte[] ciphertext = aes.encrypt(plaintext);
        byte[] decryptedText = aes.decrypt(ciphertext);
        Assertions.assertArrayEquals(plaintext, decryptedText);
    }

    @Test
    void testEncryptAndDecryptNull() {
        byte[] plaintext = null;
        Assertions.assertThrows(NullPointerException.class, () -> aes.encrypt(plaintext));
        Assertions.assertThrows(NullPointerException.class, () -> aes.decrypt(plaintext));
    }

    @Test
    public void testEncryptDecrypt16Bytes() {
        byte[] key = "0123456789abcdef".getBytes();
        AES aes = new AES(key);
        byte[] message = "Hello, world!!!".getBytes();
        byte[] encrypted = aes.encrypt(message);
        byte[] decrypted = aes.decrypt(encrypted);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptDecrypt32Bytes() {
        byte[] key = "0123456789abcdef".getBytes();
        AES aes = new AES(key);
        byte[] message = "The quick brown fox jumps over the lazy dog.".getBytes();
        byte[] encrypted = aes.encrypt(message);
        byte[] decrypted = aes.decrypt(encrypted);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptDecrypt1Byte() {
        byte[] key = "0123456789abcdef".getBytes();
        AES aes = new AES(key);
        byte[] message = new byte[] { 0x12 };
        byte[] encrypted = aes.encrypt(message);
        byte[] decrypted = aes.decrypt(encrypted);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptDecryptAllMaxValueBytes() {
        byte[] key = "0123456789abcdef".getBytes();
        AES aes = new AES(key);
        byte[] message = new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF };
        byte[] encrypted = aes.encrypt(message);
        byte[] decrypted = aes.decrypt(encrypted);
        assertArrayEquals(message, decrypted);
    }

    @Test
    public void testEncryptIfNoKeyThenThrowsAnException() {
        AES aes = new AES();
        assertThrows(Exception.class, () -> {
            aes.encrypt(new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF });
        });
    }

    @Test
    public void testEncryptIfNoKeyThenTheExceptionHasCorrectMessage() {
        AES aes = new AES();
        try {
            aes.encrypt(new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF });
        } catch (Exception e) {
            assertEquals("Failed to encrypt - No key provided", e.getMessage());
        }
    }

    @Test
    public void testDecryptIfNoKeyThenThrowsAnException() {
        AES aes = new AES();
        assertThrows(Exception.class, () -> {
            aes.decrypt(new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF });
        });
    }

    @Test
    public void testDecryptIfNoKeyThenTheExceptionHasCorrectMessage() {
        AES aes = new AES();
        try {
            aes.decrypt(new byte[] { (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF });
        } catch (Exception e) {
            assertEquals("Failed to decrypt - No key provided", e.getMessage());
        }
    }

    @Test
    public void testGenerateKeyIfThenEncryptDecryptWorks() {
        AES aes = new AES();
        aes.generateKey(AES.KEY_LENGTH.SHORT);
        byte[] plaintext = "Hello, world!".getBytes();
        byte[] ciphertext = aes.encrypt(plaintext);
        byte[] decryptedText = aes.decrypt(ciphertext);
        Assertions.assertArrayEquals(plaintext, decryptedText);
    }

    @Test
    public void testGenerateKeyIfShortLengthSpecifiedThenGeneratesKeyOfSize128Bits() {
        AES aes = new AES();
        aes.generateKey(AES.KEY_LENGTH.SHORT);
        Assertions.assertEquals(128 / Byte.SIZE, aes.getKey().length);
    }

    @Test
    public void testGenerateKeyIfMediumLengthSpecifiedThenGeneratesKeyOfSize192Bits() {
        AES aes = new AES();
        aes.generateKey(AES.KEY_LENGTH.MEDIUM);
        Assertions.assertEquals(192 / Byte.SIZE, aes.getKey().length);
    }

    @Test
    public void testGenerateKeyIfLongLengthSpecifiedThenGeneratesKeyOfSize256Bits() {
        AES aes = new AES();
        aes.generateKey(AES.KEY_LENGTH.LONG);
        Assertions.assertEquals(256 / Byte.SIZE, aes.getKey().length);
    }

    @Test
    public void testGetKey() {
        byte[] key = "0123456789abcdef".getBytes();
        AES aes = new AES(key);
        assertEquals(key, aes.getKey());
    }

    @Test
    public void TestSetKeyIfTheKeyLengthIs128BitsThenNoExceptionIsThrown() {
        byte[] key = "0123456789abcdef".getBytes();
        AES aes = new AES();
        assertDoesNotThrow(() -> aes.setKey(key));
    }

    @Test
    public void TestSetKeyIfTheKeyLengthIs192BitsThenNoExceptionIsThrown() {
        byte[] key = "0123456789abcdef01234567".getBytes();
        AES aes = new AES();
        assertDoesNotThrow(() -> aes.setKey(key));
    }

    @Test
    public void TestSetKeyIfTheKeyLengthIs256BitsThenNoExceptionIsThrown() {
        byte[] key = "0123456789abcdef0123456789abcdef".getBytes();
        AES aes = new AES();
        assertDoesNotThrow(() -> aes.setKey(key));
    }

    @Test
    public void TestSetKeyIfTheKeyLengthIsInvalidThenThrowsAnException() {
        byte[] key = "0123456789abc".getBytes();
        AES aes = new AES();
        assertThrows(Exception.class, () -> aes.setKey(key));
    }
}