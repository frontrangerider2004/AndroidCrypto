package frontrangerider.example.com.androidcrypto;

import android.os.AsyncTask;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import frontrangerider.example.com.androidcrypto.interfaces.InterfaceHashStatus;
import frontrangerider.example.com.androidcrypto.utils.LogTag;
import frontrangerider.example.com.androidcrypto.utils.SimpleHexEncoder;

/**
 * Created by emperor on 12/30/14.
 */
public class AsynchTaskHashInBackground  extends AsyncTask<Void, Void, String>{

    //For Standard Hashes
    private String mHashProvider = null;
    private String mHashAlgorithm = null;
    private String mTextToHash = null;
    private String mHashString = null;

    //For verification that the system is using what we supply
    private String mSystemAlgorithm = null;
    private String mSystemProvider = null;

    private InterfaceHashStatus mInterfaceHashStatus;

    //Constructor used to get the necessary objects into this class
    // since AsyncTask by default only accepts params of the same type
    /**
     * @param interfaceHashStatus
     * @param algorithm
     * @param textToHash
     */
    public AsynchTaskHashInBackground(InterfaceHashStatus interfaceHashStatus, String algorithm, String textToHash){
        mHashAlgorithm = algorithm;
        mTextToHash = textToHash;
        mInterfaceHashStatus = interfaceHashStatus;
    }

    @Override
    protected String doInBackground(Void... params) {
        //Do the work in here
        mHashString = hashString();
        return null;
    }

    @Override
    protected void onPostExecute(String result) {
        super.onPostExecute(result);

        //Notify the activity that it should update the UI
        mInterfaceHashStatus.onHashComplete(mHashString, mSystemProvider, mSystemAlgorithm);
    }

}//End Class
