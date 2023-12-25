package org.example;

public class Convert {

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Method that converts a hexadecimal string to a byte array.
     *
     * @param hexString hexadecimal string to be converted
     * @return byte array
     */
    public static byte[] convertHexStringToByteArray(String hexString) {
        if (! hexString.matches("[0123456789ABCDEF]*")) {
            throw new RuntimeException("Failed to convert string to hex - invalid characters");
        }
        if (hexString.length() % 2 != 0) {
            throw new RuntimeException("Failed to convert string to hex - invalid number of characters");
        }

        int stringLength = hexString.length();
        byte[] byteArray = new byte[stringLength / 2];
        for (int i = 0; i < stringLength; i += 2) {
            // Convert a pair of characters to a single byte
            byteArray[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return byteArray;
    }

    /**
     * Method that converts a byte array to a hexadecimal string.
     *
     * @param byteArray byte array to be converted
     * @return hexadecimal string
     */
    public static String convertByteArrayToHexString(byte[] byteArray) {
        char[] hexChars = new char[byteArray.length * 2];
        for (int j = 0; j < byteArray.length; j++) {
            int value = byteArray[j] & 0xFF;
            // Convert a single byte to a pair of hexadecimal characters
            hexChars[j * 2] = HEX_ARRAY[value >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[value & 0x0F];
        }
        return new String(hexChars);
    }
}
