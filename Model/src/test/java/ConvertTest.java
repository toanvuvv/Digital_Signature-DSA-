import org.example.Convert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class ConvertTest {

    @Test
    void testConvertHexStringToByteArray() {
        // Given
        String hexString = "48656C6C6F20576F726C64"; // "Hello World" in hex
        byte[] expectedByteArray = {72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100};

        // When
        byte[] actualByteArray = Convert.convertHexStringToByteArray(hexString);

        // Then
        Assertions.assertArrayEquals(expectedByteArray, actualByteArray);
    }

    @Test
    void testConvertByteArrayToHexString() {
        // Given
        byte[] byteArray = {72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100}; // "Hello World" in bytes
        String expectedHexString = "48656C6C6F20576F726C64";

        // When
        String actualHexString = Convert.convertByteArrayToHexString(byteArray);

        // Then
        Assertions.assertEquals(expectedHexString, actualHexString);
    }

    @Test
    void testRoundTripConversion() {
        // Given
        String hexString = "0123456789ABCDEF";

        // When
        byte[] byteArray = Convert.convertHexStringToByteArray(hexString);
        String actualHexString = Convert.convertByteArrayToHexString(byteArray);

        // Then
        Assertions.assertEquals(hexString, actualHexString);
    }

    @Test
    void testConvertHexStringToByteArrayIfInvalidRepresentationOfHexThenThrowsException() {
        Assertions.assertThrows(Exception.class, () -> Convert.convertHexStringToByteArray("Oh nyo~!"));
    }

    @Test
    void testConvertHexStringToByteArrayIfInvalidRepresentationOfHexThenTheExceptionHasCorrectMessage() {
        try {
            Convert.convertHexStringToByteArray("Oh nyo~!");
        } catch (Exception e) {
            Assertions.assertEquals("Failed to convert string to hex - invalid characters", e.getMessage());
        }
    }

    @Test
    void testConvertHexStringToByteArrayIfInvalidNumberOfCharactersThenThrowsException() {
        Assertions.assertThrows(Exception.class, () -> Convert.convertHexStringToByteArray("FFF"));
    }

    @Test
    void testConvertHexStringToByteArrayIfInvalidNumberOfCharactersThenExceptionHasCorrectMessage() {
        try {
            Convert.convertHexStringToByteArray("FFF");
        } catch (Exception e) {
            Assertions.assertEquals("Failed to convert string to hex - invalid number of characters",
                    e.getMessage());
        }
    }
}