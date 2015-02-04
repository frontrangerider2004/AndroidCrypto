package frontrangerider.example.com.androidcrypto;

import android.os.AsyncTask;

import frontrangerider.example.com.androidcrypto.interfaces.InterfaceHashStatus;
import frontrangerider.example.com.androidcrypto.utils.CryptoUtils;

public class AsyncTaskDoCryptoInBackground extends AsyncTask<Void, Void, String>{

    //General use fields ---------------------------------------------------
    private CryptoUtils mCryptoUtils;
    private InterfaceHashStatus mInterfaceHashStatus;

    //For Standard Hashes ---------------------------------------------------
    private String mAlgorithm;
    private char[] mMessageToHash;
    private String mHashString;


    //Constructor used to get the necessary objects into this class
    // since AsyncTask by default only accepts params of the same type
    /**
     * Creates a new instance of AsyncTask for working with crypto funcitons and configures
     * the inputs for a character array and crypto algorithm.
     * @param interfaceHashStatus
     * @param algorithm
     * @param messageToHash
     */
    public AsyncTaskDoCryptoInBackground(InterfaceHashStatus interfaceHashStatus, String algorithm, char[] messageToHash){
        mAlgorithm = algorithm;
        mMessageToHash = messageToHash;
        mInterfaceHashStatus = interfaceHashStatus;
        mCryptoUtils = new CryptoUtils();
    }

    @Override
    protected String doInBackground(Void... params) {
        //Do the work in here
        mHashString = mCryptoUtils.hashMessage(mMessageToHash, CryptoUtils.ALGORITHM_SHA256);
        return null;
    }

    @Override
    protected void onPostExecute(String result) {
        super.onPostExecute(result);

        //Notify the activity that it should update the UI
        mInterfaceHashStatus.onHashComplete(mHashString, mCryptoUtils.getmSystemHashProvider(), mCryptoUtils.getmSystemHashAlgorithm());
    }

}//End Class
