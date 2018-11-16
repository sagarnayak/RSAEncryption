package com.sagar.android.rsaencryption;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Base64;

import com.sagar.android.logutilmaster.LogUtil;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class MainActivity extends AppCompatActivity {

    @SuppressWarnings("FieldCanBeLocal")
    private LogUtil logUtil;
    public static String encrypted = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        logUtil = ((ApplicationClass) getApplicationContext()).getLogUtil();

        final RSAEncryptionMaster rsaEncryptionMaster = new RSAEncryptionMaster();
        try {
            /*
            create a key pair.
             */

            logUtil.logD("------------------------------------------------------------------------------------");
            logUtil.logD("    #### STARTING Key Tests ####    ");
            logUtil.logD("    ");
            logUtil.logD("------------------------------------------------------------------------------------");

            KeyPair keyPair = rsaEncryptionMaster.getKeyPair();
            logUtil.logD("created key pair.");
            logUtil.logD("public key is : " + keyPair.getPublic());
            logUtil.logD("private key is : " + keyPair.getPrivate());

            /*
            get the base 64 encoded string for the private and public rsa keys. which can be sent to the server or vice versa.
             */
            logUtil.logD("the base 64 private key is : " + rsaEncryptionMaster.getBase64EncodedKey(keyPair, RSAEncryptionMaster.KeyName.PRIVATE_KEY));
            logUtil.logD("the base 64 public key is : " + rsaEncryptionMaster.getBase64EncodedKey(keyPair, RSAEncryptionMaster.KeyName.PUBLIC_KEY));

            /*
            get the public key back from the bas 64 encoded string. this can be used to get back the key after it is received at
            the server or the client side.
             */
            logUtil.logD(
                    "decoded public key from encoded base 64 string: " +
                            rsaEncryptionMaster.getPublicKey(
                                    rsaEncryptionMaster.getBase64EncodedKey(
                                            keyPair,
                                            RSAEncryptionMaster.KeyName.PUBLIC_KEY
                                    )
                            )
            );

            logUtil.logD("------------------------------------------------------------------------------------");
            /*
            send a string for encryption using the public key.
            we will get the encrypted byte[] in return.
             */
            logUtil.logD("------------------------------------------------------------------------------------");
            logUtil.logD("    #### STARTING Encryption Test ####    ");
            logUtil.logD("    ");
            logUtil.logD("------------------------------------------------------------------------------------");

            String dataToEncrypt = "Sagar Nayak";
            logUtil.logD("sending data to encrypt : " + dataToEncrypt);
            byte[] data = rsaEncryptionMaster.RSAEncrypt(dataToEncrypt, keyPair.getPublic());
            logUtil.logD("\nencoded string : " + Base64.encodeToString(data,0));

            /*
            send the encrypted byte[] for decrypting the data with the help of the private key.
            this will return us the decrypted original data.
             */
            logUtil.logD("------------------------------------------------------------------------------------");
            logUtil.logD("    #### STARTING Decryption Test ####    ");
            logUtil.logD("    ");
            logUtil.logD("------------------------------------------------------------------------------------");

            String decodedString = rsaEncryptionMaster.RSADecrypt(data, keyPair.getPrivate());
            logUtil.logD("decoded string : " + decodedString);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }

         logUtil.logD("------------------------------------------------------------------------------------");
        logUtil.logD("    #### STARTING Async Encryption Test ####    ");
        logUtil.logD("    ");
        logUtil.logD("------------------------------------------------------------------------------------");
        final RSAEncryptionMaster rsaEncryptionAsync = new RSAEncryptionMaster();
        KeyPair keyPair = rsaEncryptionAsync.getKeyPair();
        logUtil.logD("created key pair.");
        logUtil.logD("public key is : " + keyPair.getPublic());
        logUtil.logD("private key is : " + keyPair.getPrivate());
        logUtil.logD("This is the text to be encrypt");



        Thread Encryption = rsaEncryptionAsync.encryptAsync("This is the text to be encrypt", keyPair.getPublic(),new RSAEncryptionMaster.Callback(){

            @Override
            public void onSuccess(String result) {
                logUtil.logD("My encrypted text: " +  result);
                encrypted = result;
                System.out.println("IS IT HERE below" + encrypted);
            }

            @Override
            public void onError(Exception e) {
                // if an error occurs you will get the exception here
                logUtil.logD("Oh no! an error has occurred: " + e);
            }
        });

        Encryption.start();                                           // Start the Thread
        try {
            Encryption.join();                                        // Waits for Encryption to finish so that we forsure have the encrypted result
        } catch (InterruptedException e) {
            e.printStackTrace();
        }


        logUtil.logD("------------------------------------------------------------------------------------");
        logUtil.logD("    #### STARTING Async Decryption Test ####    ");
        logUtil.logD("    ");
        logUtil.logD("------------------------------------------------------------------------------------");

        System.out.println("IS IT HERE" + encrypted);
        Thread Decryption = rsaEncryptionAsync.decryptAsync(encrypted, keyPair.getPrivate(),new RSAEncryptionMaster.Callback(){

            @Override
            public void onSuccess(String result) {
                logUtil.logD("\nMy encrypted text: " +  result);

            }

            @Override
            public void onError(Exception e) {
                // if an error occurs you will get the exception here
                logUtil.logD("Oh no! an error has occurred: " + e);
            }
        });
        logUtil.logD("----___--- Im back in the starting Thread ----___---");

        Decryption.start();                                           // Start the Thread
        try {
            Decryption.join();                                        // Waits for Encryption to finish so that we forsure have the encrypted result
        } catch (InterruptedException e) {
            e.printStackTrace();
        }





    }
}
