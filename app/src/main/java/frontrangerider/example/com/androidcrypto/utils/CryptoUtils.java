package frontrangerider.example.com.androidcrypto.utils;

import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class CryptoUtils {

    //General use fields ------------------------------------------
    /**
     * Recommended character encoding for use with MessageDigest
     * and hash functions.
     */
    public static final String ENCODING_UTF8 = "UTF-8";

    /**
     * The literal N/A used to represent a value is not available.
     * Provide this when CryptoUtils output contains a null string.
     */
    public static final String NA_STRING = "N/A";

    //TODO Encapsulate this enum in it's own class since it's used in more than one.
    /**
     * Enum for selecting hash output format in hex upper
     * or lower case.
     */
    public static enum HexFormatFontCase{UPPER, LOWER}

    //For use with basic hashing -----------------------------------
    //TODO Create an Enum class for holding the algorithms and
    // update the code to use these instead of the strings below.
    /**
     * The algorithm string specified by MessageDigest for
     * creating an instance that uses SHA-256. This is the
     * minimum bit length that should be used and is approved
     * for DoD Secret level protection.
     */
    public static final String ALGORITHM_SHA256 = "SHA-256"; //Approved for DoD Secret.

    /**
     * The algorithm string specified by MessageDigest for
     * creating an instance that uses SHA-512.
     */
    public static final String ALGORITHM_SHA512 = "SHA-512";

    private String mSystemProviderHash = null;
    private String mSystemAlgorithmHash = null;
    private String mHashString = null;

    //For use with Password Based Key Derivation ---------------------
    /**
     * The algorithm string specified by PBKDF2 for
     * creating a KeyFactory instance that uses PBKDF2
     * with HMAC and SHA1.
     */
    public static final String ALGORITHM_PBKDF2_HMAC_SHA1 = "PBKDF2WithHmacSHA1";
    //TODO See about using SpongyCastle provider to increase the algorithm choices

    /**
     * Integer used to specify 32 bytes should be
     * used for Salt generation. This value should
     * be equal to the hash byte length according to
     * best practice.
     */
    private static final int SALT_BYTE_SIZE = 32; //Should be equal to hash byte size

    /**
     * Integer used to specify 256 bits should be
     * used for Salt generation. This value should
     * be equal to the hash bit length according to
     * best practice.
     */
    private static final int SALT_BIT_SIZE = 256; //Conversion of bytes to bits

    /**
     * Integer used to specify the minimum number of PBKDF hash
     * rounds to perform for HMAC algorithms. The PBKDF2 spec
     * recommends a mimimum of 1000 rounds, which should then
     * be adjusted for computing performance to produce an
     * acceptable delay (AKA computational penalty).
     */
    private static final int PBKDF2_MIN_ITERATIONS = 1000; //Minimum required per the PBKDF2 spec

    private byte[] mSalt = null;
    private String mPBKDFprovider = null;
    private String mPBKDFalgorithm = null;
    private int mPBKDFiterations = 0;
    private int mSaltBitLength = 0;
    private String mPBKDFhashString = null;

    //Getters and Setters -----------------------------------------------------

    public String getmSystemProviderHash() {
        return mSystemProviderHash;
    }

    public String getmSystemAlgorithmHash() {
        return mSystemAlgorithmHash;
    }

    /**
     * Convert each character in the supplied array to bytes assuming
     * each char is one byte meaning either ASCII or UTF8 encoding.
     * @param charsUTF8encoded
     * @return
     */
    private byte[] convertCharacterArrayToBytes(char[] charsUTF8encoded){
        byte[] messageBytes = null;
        for(int i = 0; i <= ((charsUTF8encoded.length - 1)); i++){
            messageBytes[i] = (byte) charsUTF8encoded[i];
        }

        return messageBytes;
    }

    /**
     * Creates an instance of the SimpleHexEncoder utility with the
     * given FontCase.
     * @param hexFormatFontCase
     * @return
     * @throws UnsupportedEncodingException if the format type is not recognized
     */
    private SimpleHexEncoder generateHexEncoder(HexFormatFontCase hexFormatFontCase){
        SimpleHexEncoder hexEncoder = null;

        switch(hexFormatFontCase){
            case LOWER:
                hexEncoder = new SimpleHexEncoder(SimpleHexEncoder.FontCase.LOWER);
                break;
            case UPPER:
                hexEncoder = new SimpleHexEncoder(SimpleHexEncoder.FontCase.UPPER);
                break;
            default:
                Log.d(LogTag.TAG, "Cannot create SimpleHexEncoder, unknown FontCase. Should be Upper or Lower.");
                break;
        }

        return hexEncoder;
    }

    /**
     * Generates a hash of the supplied message using the specified hash algorithm
     * and formats the result as either upper or lower case hexidecimal depending
     * on the supplied font case.
     * @param messageUTF8encoded
     * @param algorithmName
     * @param hexFormatFontCase
     * @return - The hex encoded string of the hash from it's byte array
     */
    public String hashMessage(char[] messageUTF8encoded, String algorithmName, HexFormatFontCase hexFormatFontCase){
        MessageDigest messageDigest = null;
        byte[] digestBytes = null;

        //Generate the hash of the supplied message
        try {
            messageDigest = MessageDigest.getInstance(algorithmName);
            messageDigest.update(convertCharacterArrayToBytes(messageUTF8encoded)); //Each call to update will reset the digest.
            digestBytes = messageDigest.digest(); //Get the raw bytes after hashing is complete.
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        //For the UI
        if(messageDigest.getAlgorithm() != null){
            mSystemAlgorithmHash = messageDigest.getAlgorithm();
            Log.d(LogTag.TAG, "hashString(): messageDigest.getAlgorithm(): " + messageDigest.getAlgorithm());
        } else {
            mSystemAlgorithmHash = NA_STRING;
        }

        //For the UI
        if(messageDigest.getProvider().getName() != null){
            mSystemProviderHash = messageDigest.getProvider().getName();
            Log.d(LogTag.TAG, "hashString(): messageDigest.getProvider(): " + messageDigest.getProvider().getName());
        } else {
            mSystemProviderHash = NA_STRING;
        }

        Log.d(LogTag.TAG, "hashString(): Successfully hashed the input string.");
        return generateHexEncoder(hexFormatFontCase).encodeHexString(digestBytes); //The hash of the text in hex encoding
    }

    /**
     * Generates a hash of the supplied message using the specified hash algorithm
     * and formats the result as a lower case hexidecimal string.
     * @param messageUTF8Encoded
     * @param algorithmName
     * @return
     */
    public String hashMessage(char[] messageUTF8Encoded, String algorithmName){
        return hashMessage(messageUTF8Encoded, algorithmName, HexFormatFontCase.LOWER);
    }

}//End Class
