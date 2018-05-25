package com.sagar.android.rsaencryption;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;

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

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);

        logUtil = ((ApplicationClass) getApplicationContext()).getLogUtil();

        RSAEncryptionMaster rsaEncryptionMaster = new RSAEncryptionMaster();
        try {
            /*
            create a key pair.
             */
            KeyPair keyPair = rsaEncryptionMaster.getKeyPair();
            logUtil.logD("created key pair.");
            logUtil.logD("public key is : " + keyPair.getPublic());
            logUtil.logD("private key is : " + keyPair.getPrivate());

            /*
            get the base 64 encoded string for the private and public rsa keys. which can be sent to the server or vice versa.
             */
            logUtil.logE("the base 64 private key is : " + rsaEncryptionMaster.getBase64EncodedKey(keyPair, RSAEncryptionMaster.KeyName.PRIVATE_KEY));
            logUtil.logE("the base 64 public key is : " + rsaEncryptionMaster.getBase64EncodedKey(keyPair, RSAEncryptionMaster.KeyName.PUBLIC_KEY));

            /*
            get the public key back from the bas 64 encoded string. this can be used to get back the key after it is received at
            the server or the client side.
             */
            logUtil.logW(
                    "decoded public key from encoded base 64 string: " +
                            rsaEncryptionMaster.getPublicKey(
                                    rsaEncryptionMaster.getBase64EncodedKey(
                                            keyPair,
                                            RSAEncryptionMaster.KeyName.PUBLIC_KEY
                                    )
                            )
            );

            /*
            send a string for encryption using the public key.
            we will get the encrypted byte[] in return.
             */
            String dataToEncrypt = "Sagar Nayak";
            logUtil.logD("sending data to encrypt : " + dataToEncrypt);
            byte[] data = rsaEncryptionMaster.RSAEncrypt(dataToEncrypt, keyPair.getPublic());
            logUtil.logD("encoded string : " + new String(data, "UTF-8"));

            /*
            send the encrypted byte[] for decrypting the data with the help of the private key.
            this will return us the decrypted original data.
             */
            String decodedString = rsaEncryptionMaster.RSADecrypt(data, keyPair.getPrivate());
            logUtil.logD("decoded string : " + decodedString);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }
}
