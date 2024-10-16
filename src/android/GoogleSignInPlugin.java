package com.devapps;

import android.app.Activity;
import android.content.Context;
import android.os.CancellationSignal;

import androidx.annotation.NonNull;
import androidx.credentials.ClearCredentialStateRequest;
import androidx.credentials.Credential;
import androidx.credentials.CredentialManager;
import androidx.credentials.CredentialManagerCallback;
import androidx.credentials.GetCredentialRequest;
import androidx.credentials.GetCredentialResponse;
import androidx.credentials.exceptions.ClearCredentialException;
import androidx.credentials.exceptions.GetCredentialException;

import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.apache.cordova.CordovaWebView;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.libraries.identity.googleid.GetGoogleIdOption;
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption;
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential;
import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.FirebaseAuth;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class GoogleSignInPlugin extends CordovaPlugin {
    private GoogleSignInAccount account;
    private FirebaseAuth mAuth;

    private Context mContext;
    private Activity mCurrentActivity;
    private CallbackContext mCallbackContext;

    @Override
    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);
        mCurrentActivity = this.cordova.getActivity();
        mContext = mCurrentActivity.getApplicationContext();
        mAuth = FirebaseAuth.getInstance();
        FirebaseApp.initializeApp(mContext);
    }

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        switch (action) {
            case Constants.CORDOVA_ACTION_IS_SIGNEDIN:
                this.isSignedIn(callbackContext);
                return true;
            case Constants.CORDOVA_ACTION_DISCONNECT:
                this.disconnect(callbackContext);
                return true;
            case Constants.CORDOVA_ACTION_SIGNIN:
                this.signIn(callbackContext);
                return true;
            case Constants.CORDOVA_ACTION_SIGNOUT:
                this.signOut(callbackContext);
                return true;
        }
        return false;
    }

    private void isSignedIn(CallbackContext callbackContext) {
        boolean isSignedIn = (account != null || mAuth.getCurrentUser() != null);
        callbackContext.success(getSuccessMessageInJsonString(String.valueOf(isSignedIn)));
    }

    private void disconnect(CallbackContext callbackContext) {
        callbackContext.error(getErrorMessageInJsonString("Not available on Android."));
    }

    private void signIn(CallbackContext callbackContext) {
        mCallbackContext = callbackContext;
        signIn();
    }

    private void signOut(CallbackContext callbackContext) {
        mCallbackContext = callbackContext;
        signOut();
    }

    private void signIn() {
        cordova.setActivityResultCallback(this);
        CredentialManager credentialManager = CredentialManager.create(mContext);
        CancellationSignal cancellationSignal = new CancellationSignal();
        ExecutorService executor = Executors.newSingleThreadExecutor();

        // attempt auto signin
        GetGoogleIdOption googleIdOption = new GetGoogleIdOption.Builder()
                .setFilterByAuthorizedAccounts(false)
                .setServerClientId(this.cordova.getActivity().getResources()
                        .getString(getAppResource()))
                .setAutoSelectEnabled(true)
                .setNonce(generateNonce()).build();

        GetCredentialRequest request = new GetCredentialRequest.Builder()
                .addCredentialOption(googleIdOption)
                .build();

        credentialManager.getCredentialAsync(
                mCurrentActivity,
                request,
                cancellationSignal,
                executor,
                new CredentialManagerCallback<GetCredentialResponse, GetCredentialException>() {
                    @Override
                    public void onResult(GetCredentialResponse result) {
                        handleSignIn(result);
                    }

                    @Override
                    public void onError(@NonNull GetCredentialException e) {
                        doManualSignIn();
                    }
                });
    }

    private void doManualSignIn() {
        CredentialManager credentialManager = CredentialManager.create(mContext);
        CancellationSignal cancellationSignal = new CancellationSignal();
        ExecutorService executor = Executors.newSingleThreadExecutor();

        GetSignInWithGoogleOption googleIdOption = new GetSignInWithGoogleOption.Builder(
                this.cordova.getActivity().getResources()
                        .getString(getAppResource()))
                .setNonce(generateNonce()).build();

        GetCredentialRequest request = new GetCredentialRequest.Builder()
                .addCredentialOption(googleIdOption)
                .build();

        credentialManager.getCredentialAsync(
                mCurrentActivity,
                request,
                cancellationSignal,
                executor,
                new CredentialManagerCallback<GetCredentialResponse, GetCredentialException>() {
                    @Override
                    public void onResult(GetCredentialResponse result) {
                        handleSignIn(result);
                    }

                    @Override
                    public void onError(@NonNull GetCredentialException e) {
                        mCallbackContext.error(getErrorMessageInJsonString(e.getMessage()));
                    }
                });
    }

    private void handleSignIn(GetCredentialResponse result) {
        // Handle the successfully returned credential.
        Credential credential = result.getCredential();

        if (credential.getType().equals(GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL)) {
            GoogleIdTokenCredential googleIdTokenCredential = GoogleIdTokenCredential
                    .createFrom((credential).getData());

            String idToken = googleIdTokenCredential.getIdToken();
            respondWithGoogleToken(idToken);
        }
    }

    private void signOut() {
        CredentialManager credentialManager = CredentialManager.create(mContext);
        ClearCredentialStateRequest request = new ClearCredentialStateRequest();
        CancellationSignal cancellationSignal = new CancellationSignal();
        ExecutorService executor = Executors.newSingleThreadExecutor();

        credentialManager.clearCredentialStateAsync(
                request,
                cancellationSignal,
                executor,
                new CredentialManagerCallback<Void, ClearCredentialException>() {
                    @Override
                    public void onResult(Void unused) {
                        account = null;
                        mCallbackContext.success(getSuccessMessageInJsonString("Logged out"));
                    }

                    @Override
                    public void onError(@NonNull ClearCredentialException e) {
                        mCallbackContext.error(getErrorMessageInJsonString(e.getMessage()));
                    }
                });
    }

    private void respondWithGoogleToken(String idToken) {
        try {
            JSONObject userInfo = new JSONObject();
            userInfo.put("id_token", idToken);
            mCallbackContext.success(getSuccessMessageForOneTapLogin(userInfo));
        } catch (Exception ex) {
            mCallbackContext.error(getErrorMessageInJsonString(ex.getMessage()));
        }
    }

    private int getAppResource() {
        return cordova.getActivity().getResources().getIdentifier("default_client_id", "string",
                cordova.getActivity().getPackageName());
    }

    private String getSuccessMessageForOneTapLogin(JSONObject userInfo) {
        try {
            JSONObject response = new JSONObject();
            response.put(Constants.JSON_STATUS, Constants.JSON_SUCCESS);
            response.put(Constants.JSON_MESSAGE, userInfo);
            return response.toString();
        } catch (JSONException e) {
            return "{\"status\": \"error\", \"message\": \"JSON error while building the response\"}";
        }
    }

    private String getSuccessMessageInJsonString(String message) {
        try {
            JSONObject response = new JSONObject();
            response.put(Constants.JSON_STATUS, Constants.JSON_SUCCESS);
            response.put(Constants.JSON_MESSAGE, message);
            return response.toString();
        } catch (JSONException e) {
            return "{\"status\": \"error\", \"message\": \"JSON error while building the response\"}";
        }
    }

    private String getErrorMessageInJsonString(String errorMessage) {
        try {
            JSONObject response = new JSONObject();
            response.put(Constants.JSON_STATUS, Constants.JSON_ERROR);
            response.put(Constants.JSON_MESSAGE, errorMessage);
            return response.toString();
        } catch (JSONException e) {
            return "{\"status\": \"error\", \"message\": \"JSON error while building the response\"}";
        }
    }

    private String generateNonce() {
        try {
            String ranNonce = UUID.randomUUID().toString();
            byte[] bytes = ranNonce.getBytes();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            StringBuilder hashedNonce = new StringBuilder();
            for (byte b : digest) {
                hashedNonce.append(String.format("%02x", b));
            }
            return hashedNonce.toString();
        } catch (NoSuchAlgorithmException e) {
            mCallbackContext.error(getErrorMessageInJsonString(e.getMessage()));
            return null;
        }
    }
}