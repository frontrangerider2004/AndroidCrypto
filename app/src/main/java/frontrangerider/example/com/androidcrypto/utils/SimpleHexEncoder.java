package frontrangerider.example.com.androidcrypto.utils;

import android.util.Log;

/**
 * Created by emperor on 12/31/14.
 */
public class SimpleHexEncoder {

    /**
     * The format string to use for Hexidecimal output via
     * StringFormatter. Reads two bytes and prints as lower
     * case hex
     */
    public static final String FORMATTER_HEX_LOWER = "%02x"; //Read two bytes as lower case hex

    /**
     * The format string to use for Hexidecimal output via
     * StringFormatter. Reads two bytes and prints as upper
     * case hex
     */
    public static final String FORMATTER_HEX_UPPER = "%02X"; //Read two bytes as upper case hex
    private String hexFormatStyle = null;

    //TODO Encapsulate this enum in it's own class since it's used in more than one.
    /**
     * Enum to specify the font case of either upper
     * or lower during creation of the hex formatter.
     */
    public static enum FontCase{UPPER, LOWER}

    /**
     * Creates a simple hex encoder that uses string
     * formatters to encode bytes to hex.
     * @param fontCaseEnum
     */
    public SimpleHexEncoder(FontCase fontCaseEnum){

        switch (fontCaseEnum){
            case UPPER:
                hexFormatStyle = FORMATTER_HEX_UPPER;
                break;
            case LOWER:
                hexFormatStyle = FORMATTER_HEX_LOWER;
                break;
            default:
                break;
        }

    }

    /**
     * Takes a Message Digest or any other byte
     * array and converts it into a hexidecimal
     * string using a format string for hex.
     * @param byteArray
     * @return
     */
    public String encodeHexString(byte[] byteArray){
        StringBuilder sb = new StringBuilder();

        for(byte b : byteArray){
            sb.append(String.format(hexFormatStyle, b));
        }

        Log.d(LogTag.TAG, "encodeHexString(): Byte array encoded to HEX string.");

        return sb.toString();
    }

}//End Class
