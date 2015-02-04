package frontrangerider.example.com.androidcrypto.interfaces;

public interface InterfaceHashStatus {

    /**
     * Callback for notifying that a hash has been completed
     * in a background thread.
     * @param hashString
     * @param provider
     * @param algorithm
     */
    public void onHashComplete(String hashString, String provider, String algorithm);

    public void onPBKDF2Complete(String hashString, int keyBitLength, String provider, String algorithm, String salt, int saltBitLength, int iterations);

}//End Interface
