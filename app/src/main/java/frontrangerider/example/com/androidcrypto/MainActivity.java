package frontrangerider.example.com.androidcrypto;

import android.content.Context;
import android.content.res.Resources;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;

import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Button;

import frontrangerider.example.com.androidcrypto.interfaces.InterfaceHashStatus;
import frontrangerider.example.com.androidcrypto.utils.CryptoUtils;
import frontrangerider.example.com.androidcrypto.utils.LogTag;

public class MainActivity extends ActionBarActivity implements InterfaceHashStatus {

    //User input and control
    private EditText editTextInput;
    private Button buttonHash;

    //Regular Hashing UI
    private TextView textViewHash;
    private TextView textViewHashAlgorithm;
    private TextView textViewHashProvider;

    //PBKDF Hashing UI
    private TextView textViewPBKDFhash;
    private TextView textViewPBKDFkeyBitLength;
    private TextView textviewPBKDFAlgorithm;
    private TextView textviewPBKDiterations;
    private TextView textviewPBKDFprovider;
    private TextView textviewPBKDFsalt;
    private TextView textviewPBKDFsaltBitLength;

    private Resources mResources;

    private Context mContext;

    private InterfaceHashStatus interfaceHashStatus;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mResources = getResources();
        mContext = getApplicationContext();
        interfaceHashStatus = this;

        //User inputs
        editTextInput = (EditText) findViewById(R.id.editText_input);
        buttonHash = (Button) findViewById(R.id.button_hash);

        //Plain Hashing UI
        textViewHash = (TextView) findViewById(R.id.textView_hashed);
        textViewHashAlgorithm = (TextView) findViewById(R.id.textView_hashed_algorithm);
        textViewHashProvider = (TextView) findViewById(R.id.textView_hashed_provider);

        //PBKDF Hashing UI
        textViewPBKDFhash = (TextView) findViewById(R.id.textView_pbkdf_hashed);
        textViewPBKDFkeyBitLength = (TextView) findViewById(R.id.textView_pbkdf_key_bit_length);
        textviewPBKDFsalt = (TextView) findViewById(R.id.textView_pbkdf_salt);
        textviewPBKDFAlgorithm = (TextView) findViewById(R.id.textView_pbkdf_algorithm);
        textviewPBKDFprovider = (TextView) findViewById(R.id.textView_pbkdf_provider);
        textviewPBKDFsaltBitLength = (TextView) findViewById(R.id.textView_pbkdf_salt_bitLength);
        textviewPBKDiterations = (TextView) findViewById(R.id.textView_pbkdf_iterations);

        registerClickListeners();

        resetTextViews();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    /**
     * Handles button clicks for the "hash" button.
     */
    View.OnClickListener hashButtonClickListener = new View.OnClickListener() {
        @Override
        public void onClick(View v) {

            hideKeyboard();

            //TODO Hash the string normally
            new AsyncTaskDoCryptoInBackground(interfaceHashStatus, AsyncTaskDoCryptoInBackground.CryptoOperation.HASH, CryptoUtils.ALGORITHM_SHA256, getTextInputAsCharacterArray(editTextInput)).execute();

            //TODO hash the string with the PBKDF methods
            new AsyncTaskDoCryptoInBackground(interfaceHashStatus, AsyncTaskDoCryptoInBackground.CryptoOperation.PBKDF2, CryptoUtils.ALGORITHM_PBKDF2_HMAC_SHA1, CryptoUtils.PBKDF2_MIN_ITERATIONS, CryptoUtils.SALT_BIT_SIZE, getTextInputAsCharacterArray(editTextInput)).execute();
        }
    };

    /**
     * Sets the "hash" button click listener to the
     * cutstom listener defined above.
     */
    private void registerClickListeners(){

        buttonHash.setOnClickListener(hashButtonClickListener);
    }

    /**
     * Extracts the user supplied text from an EditText and
     * stores it in a character array.
     * @param editText
     * @return
     */
    private char[] getTextInputAsCharacterArray(EditText editText){
        //The EditText object supposedly uses char[] at the core so we don't need
        // to worry about string objects remaining for passwords and can extract the chars directly.
        char[] inputMessageChars = new char[getInputTextLength(editTextInput)];
        editTextInput.getText().getChars(0, getInputTextLength(editTextInput), inputMessageChars, 0);
        Log.d(LogTag.TAG, "getTextInputAsCharacterArray = " + inputMessageChars.toString());
        //TODO Call the CryptoUtils.secure erase method in the onPause() of this to erase our chars
        return inputMessageChars;
    }

    /**
     * Returns the length of the char[] from the
     * supplied EditText.
     * @param editText
     * @return
     */
    private int getInputTextLength(EditText editText){
        return editText.getText().length();
    }

    /**
     * Forces the soft keyboard to close so we can
     * see the entire screen.
     */
    private void hideKeyboard(){
        //Hide the keyboard so we can see the screen
        InputMethodManager inputManager = (InputMethodManager)
                getSystemService(Context.INPUT_METHOD_SERVICE);

        inputManager.hideSoftInputFromWindow(getCurrentFocus().getWindowToken(),
                InputMethodManager.HIDE_NOT_ALWAYS);
    }

    private void setText(TextView tv, String text){
        tv.setText(text);
    }

    private void setText(TextView tv, int formatterResourceId, String text){
        tv.setText(String.format(mResources.getString(formatterResourceId), text));
    }

    private void setText(TextView tv, int formatterResourceId, int number){
        tv.setText(String.format(mResources.getString(formatterResourceId), number));
    }

    private void resetStringText(TextView tv, int formatterResourceId){
        tv.setText(String.format(mResources.getString(formatterResourceId), mResources.getString(R.string.empty)));
    }

    private void resetIntegerText(TextView tv, int formatterResourceId){
        tv.setText(String.format(mResources.getString(formatterResourceId), 0));
    }

    /**
     * Sets all String formatted TextViews to the empty
     * string and all decimal formatted TextViews to '0'.
     */
    private void resetTextViews(){
        //Regular Hash UI elements
        resetStringText(textViewHashAlgorithm, R.string.hash_algorithm);
        resetStringText(textViewHashProvider, R.string.hash_provider);

        //PBKDF2 UI Elements
        resetStringText(textviewPBKDFAlgorithm, R.string.pbkdf_algorithm);
        resetIntegerText(textViewPBKDFkeyBitLength, R.string.pbkdf_key_bitLength);
        resetStringText(textviewPBKDFprovider, R.string.pbkdf_provider);
        resetStringText(textviewPBKDFsalt, R.string.pbkdf_salt);
        resetIntegerText(textviewPBKDFsaltBitLength, R.string.pbkdf_salt_bitLength);
        resetIntegerText(textviewPBKDiterations, R.string.pbkdf_iterations);

    }

    // ============ Callbacks for Updating the User Interface After Hashing Complete ======== //
    @Override
    public void onHashComplete(String hashString, String provider, String algorithm) {
        Log.d(LogTag.TAG, "onHashComplete(): hashString= " + hashString + ", Provider= " + provider + ", Algorithm= " + algorithm);
        setText(textViewHash, hashString);
        setText(textViewHashAlgorithm, R.string.hash_algorithm, algorithm);
        setText(textViewHashProvider, R.string.hash_provider, provider);
        //TODO Implement textViews that show bit count of the hash and input

    }

    @Override
    public void onPBKDF2Complete(String hashString, int keyBitLength, String provider, String algorithm, String salt, int saltBitLength, int iterations) {
        Log.d(LogTag.TAG, "onPBKDFhashComplete()");
        //TODO Implement calls to set the PBKDF2 UI elements
        setText(textViewPBKDFhash, hashString);
        setText(textViewPBKDFkeyBitLength, R.string.pbkdf_key_bitLength, keyBitLength);
        setText(textviewPBKDFprovider, R.string.pbkdf_provider, provider);
        setText(textviewPBKDFAlgorithm, R.string.pbkdf_algorithm, algorithm);
        setText(textviewPBKDFsalt, R.string.pbkdf_salt, salt);
        setText(textviewPBKDFsaltBitLength, R.string.pbkdf_salt_bitLength, saltBitLength);
        setText(textviewPBKDiterations, R.string.pbkdf_iterations, iterations);
    }

}//End Class
