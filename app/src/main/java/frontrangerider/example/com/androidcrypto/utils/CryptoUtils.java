package frontrangerider.example.com.androidcrypto.utils;

import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

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

    /**
     * Stores the conversion of the supplied character array
     * into bytes.
     */
    private byte[] mMessageBytes = null;

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

    private String mSystemHashProvider = null;
    private String mSystemHashAlgorithm = null;
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

    /**
     * Returns the Security Provider used to perform
     * regular hashing or Null if @call hashMessage() has
     * not been called.
     * @return
     */
    public String getmSystemHashProvider() {
        return mSystemHashProvider;
    }

    /**
     * Returns the Security Provider's algorithm used to perform
     * regular hashing or Null if @call hashMessage() has
     * not been called. This can be used to compared what the
     * system is using to what has been specified at time of
     * initialization.
     * @return
     */
    public String getmSystemHashAlgorithm() {
        return mSystemHashAlgorithm;
    }

    /**
     * Replace all characters in the array with zeros per the
     * Sun Java recommended method for handling password inputs.
     * @param chars
     */
    public static void secureOverwriteCharacterArray(char[] chars){
        if(chars != null && chars.length > 0){
            Arrays.fill(chars, '0');
            Log.d(LogTag.TAG, "secureOverwriteCharacterArray() complete! ");
        } else {
            Log.d(LogTag.TAG, "secureOverwriteCharacterArray() ERROR: Attempted to overwrite null array");
        }

    }

    /**
     * Replace all the bytes in the array with zeros per the
     * Sun Java recommended method for handling password inputs.
     * @param bytes
     */
    public static void secureOverwriteByteArray(byte[] bytes){
        if(bytes != null && bytes.length > 0){
            Arrays.fill(bytes, (byte) 0);
            Log.d(LogTag.TAG, "secureOverwriteByteArray() complete!");
        } else {
            Log.d(LogTag.TAG, "secureOverwriteByteArray() ERROR: Attempted to overwrite null array");
        }

    }

    /**
     * Convert each character in the supplied array to bytes assuming
     * each char is one byte meaning either ASCII or the ASCII set of
     * UTF8 encoding.
     * @param charsUTF8encoded
     * @return
     */
    private byte[] convertCharacterArrayToBytes(char[] charsUTF8encoded){
        //NOTE: If using the full UTF-8 encoding set this will not work
        // becuse some characters can hve up to 4 bytes.

        //If we somehow have a byte[] sitting around then erase it first.
        if(mMessageBytes != null && mMessageBytes.length > 0){
            secureOverwriteByteArray(mMessageBytes);
        }
        
        mMessageBytes = new byte[charsUTF8encoded.length];
        for(int i = 0; i <= ((charsUTF8encoded.length - 1)); i++){
            mMessageBytes[i] = (byte) charsUTF8encoded[i];
        }

        return mMessageBytes;
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
                Log.d(LogTag.TAG, "SimpleHexEncoder created for LOWER CASE.");
                break;
            case UPPER:
                hexEncoder = new SimpleHexEncoder(SimpleHexEncoder.FontCase.UPPER);
                Log.d(LogTag.TAG, "SimpleHexEncoder created for UPPER CASE.");
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

        Log.d(LogTag.TAG, "hashMessage(): Attempting to configure a MessageDigest...");
        //Generate the hash of the supplied message
        try {
            messageDigest = MessageDigest.getInstance(algorithmName);
            messageDigest.update(convertCharacterArrayToBytes(messageUTF8encoded)); //Each call to update will reset the digest.
            digestBytes = messageDigest.digest(); //Get the raw bytes after hashing is complete.
            Log.d(LogTag.TAG, "hashMessage(): MessageDigest successfully created!");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        //For the UI
        if(messageDigest.getAlgorithm() != null){
            mSystemHashAlgorithm = messageDigest.getAlgorithm();
            Log.d(LogTag.TAG, "hashMessage(): messageDigest.getAlgorithm(): " + messageDigest.getAlgorithm());
        } else {
            mSystemHashAlgorithm = NA_STRING;
        }

        //For the UI
        if(messageDigest.getProvider().getName() != null){
            mSystemHashProvider = messageDigest.getProvider().getName();
            Log.d(LogTag.TAG, "hashMessage(): messageDigest.getProvider(): " + messageDigest.getProvider().getName());
        } else {
            mSystemHashProvider = NA_STRING;
        }

        //Erase the supplied character array and the generated array
        // used to convert from chars to bytes.
        secureOverwriteCharacterArray(messageUTF8encoded);
        secureOverwriteByteArray(mMessageBytes);

        Log.d(LogTag.TAG, "hashMessage(): SUCCESS!");
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

    //    /**
//     * Gets the specified number of secure random bytes
//     * using the javax security API and returns this
//     * array for use as a salt in PBKD functions.
//     * @param numberOfBytes
//     * @return
//     */
//    private byte[] generateSaltBytes(int numberOfBytes){
//        SecureRandom secureRandom = new SecureRandom();
//        byte[] salt = new byte[numberOfBytes];
//        secureRandom.nextBytes(salt);
//
//        Log.d(TAG, "generateSaltBytes(): Salt generation complete.");
//
//        setmSalt(salt);
//
//        return salt;
//    }
//
//    /**
//     * Generates a keyed, stretched, and multi-iterated
//     * hash of the supplied character array using the
//     * supplied algorithm and number of iterations.
//     * @param password
//     * @param saltBitLength
//     * @param pbkdfAlgorithm
//     * @param iterations
//     * @return
//     */
//    private String pbkdfHashString(char[] password, String pbkdfAlgorithm, int iterations, int saltBitLength){
//        //Generate secure random salt
//        byte[] salt = generateSaltBytes(saltBitLength);
//        setmSaltBitLength(saltBitLength);
//
//        //Setup the PBKD function
//        PBEKeySpec keySpec = new PBEKeySpec(password, salt, iterations, saltBitLength);
//        setmPBKDFiterations(iterations);
//
//        byte[] hashedBytes = null;
//        SecretKeyFactory keyFactory = null;
//
//        try{
//            keyFactory = SecretKeyFactory.getInstance(PBKDF_ALGORITHM);
//            hashedBytes = keyFactory.generateSecret(keySpec).getEncoded();
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        } catch (InvalidKeySpecException e) {
//            e.printStackTrace();
//        }
//
//        //For the UI
//        Log.d(TAG, "pbkdfHashString(): secretKeyFactory.getProvider(): " + keyFactory.getProvider() + ", kf.getAlgorithm(): " + keyFactory.getAlgorithm());
//        if(keyFactory.getProvider().getName() != null){
//            setmPBKDFprovider(keyFactory.getProvider().getName());
//        } else {
//            setmPBKDFprovider(NA_STRING);
//        }
//
//        //For the UI
//        if(keyFactory.getAlgorithm().toString() != null){
//            setmPBKDFalgorithm(keyFactory.getAlgorithm().toString());
//        } else {
//            setmPBKDFalgorithm(NA_STRING);
//        }
//
//        //For the UI
//        if(hashedBytes == null){
//            Log.d(TAG, "pbkdfHashString(): hashedBytes = NULL");
//            return null;
//        }
//
//        Log.d(TAG, "pbkdfHashString(): PBKDF hash generated successfully.");
//        return encodeHexString(hashedBytes); //Hash of the input in hex encoding
//    }

}//End Class
