package frontrangerider.example.com.androidcrypto;

import android.os.AsyncTask;
import android.util.Log;

import frontrangerider.example.com.androidcrypto.interfaces.InterfaceHashStatus;
import frontrangerider.example.com.androidcrypto.utils.CryptoUtils;
import frontrangerider.example.com.androidcrypto.utils.LogTag;

public class AsyncTaskDoCryptoInBackground extends AsyncTask<Void, Void, String>{

    //General use fields ---------------------------------------------------
    private CryptoUtils mCryptoUtils;
    private InterfaceHashStatus mInterfaceHashStatus;

    //For Standard Hashes ---------------------------------------------------
    private String mAlgorithm;
    private char[] mCharsToHash;
    private String mHashString;

    //For PBKDF
    int mIterations;
    int mKeyBitLength;

    public static enum CryptoOperation{HASH, PBKDF2, PKI}

    private CryptoOperation mMode;

    //Constructor used to get the necessary objects into this class
    // since AsyncTask by default only accepts params of the same type
    /**
     * Creates a new instance of AsyncTask for working with crypto funcitons and configures
     * the inputs for a character array and crypto algorithm.
     * @param interfaceHashStatus
     * @param algorithm
     * @param messageToHash
     */
    public AsyncTaskDoCryptoInBackground(InterfaceHashStatus interfaceHashStatus, CryptoOperation cryptoOperation, String algorithm, char[] messageToHash){
        mAlgorithm = algorithm;
        mCharsToHash = messageToHash;
        mInterfaceHashStatus = interfaceHashStatus;
        mMode = cryptoOperation;
        mCryptoUtils = new CryptoUtils();
    }

    public AsyncTaskDoCryptoInBackground(InterfaceHashStatus interfaceHashStatus, CryptoOperation cryptoOperation, String algorithm, int iterationsPBKDF, int keyBitLength, char[] password){
        mAlgorithm = algorithm;
        mCharsToHash = password;
        mInterfaceHashStatus = interfaceHashStatus;
        mMode = cryptoOperation;
        mIterations = iterationsPBKDF;
        mKeyBitLength = keyBitLength;
        mCryptoUtils = new CryptoUtils();
    }

    @Override
    protected String doInBackground(Void... params) {
        //Do the work in here
        switch (mMode){
            case HASH:
                mHashString = computeHash();
                break;
            case PBKDF2:
                mHashString = computePBKDF2();
                break;
            default:
                Log.d(LogTag.TAG, "doInBackground(): ERROR unknown crypto operation requested!");
                break;
        }

        return null;
    }

    @Override
    protected void onPostExecute(String result) {
        super.onPostExecute(result);

        //Notify the activity that it should update the UI
        switch (mMode){
            case HASH:
                mInterfaceHashStatus.onHashComplete(mHashString, mCryptoUtils.getmSystemHashProvider(), mCryptoUtils.getmSystemHashAlgorithm());
                break;
            case PBKDF2:
                mInterfaceHashStatus.onPBKDF2Complete(mHashString, mCryptoUtils.getmPBKDF2keyBitLength(), mCryptoUtils.getmSystemPBKDF2provider(), mCryptoUtils.getmSystemPBKDF2algorithm(), mCryptoUtils.getmSaltString(), mCryptoUtils.getmSaltBitLength(), mIterations);
                break;
            default:
                Log.d(LogTag.TAG, "onPostExecute(): ERROR unknown crypto operation requested!");
                break;
        }

    }

    /**
     * Calls the @code CryptoUtils hash function for non
     * PBKDF2 hashing.
     * @return
     */
    private String computeHash(){
        return mCryptoUtils.hashMessage(mCharsToHash, mAlgorithm);
    }

    /**
     * Calls the @code CryptoUtils hash function for PBKDF2
     * key generation.
     * @return
     */
    private String computePBKDF2(){
        return mCryptoUtils.generatePBKDF2Key(mCharsToHash, mAlgorithm, mIterations, mKeyBitLength);
    }

}//End Class
