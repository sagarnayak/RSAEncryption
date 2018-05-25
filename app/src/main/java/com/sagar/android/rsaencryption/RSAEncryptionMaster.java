package com.sagar.android.rsaencryption;

import android.util.Base64;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSAEncryptionMaster {

    public byte[] RSAEncrypt(final String plain, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {


        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plain.getBytes());
    }

    public String RSADecrypt(final byte[] encryptedBytes, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher1 = Cipher.getInstance("RSA");
        cipher1.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher1.doFinal(encryptedBytes);
        String decrypted = new String(decryptedBytes);
        System.out.println("DDecrypted?????" + decrypted);
        return decrypted;
    }

    public KeyPair getKeyPair() {
        KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        //noinspection ConstantConditions
        kpg.initialize(2048);
        return kpg.genKeyPair();
    }

    public enum KeyName {
        PUBLIC_KEY,
        PRIVATE_KEY
    }

    public String getBase64EncodedKey(KeyPair keyPair, KeyName keyName) {
        if (keyName == KeyName.PUBLIC_KEY) {
            return new String(
                    Base64.encode(
                            keyPair.getPublic().getEncoded(),
                            Base64.NO_WRAP
                    )
            );
        } else if (keyName == KeyName.PRIVATE_KEY) {
            return new String(
                    Base64.encode(
                            keyPair.getPrivate().getEncoded(),
                            Base64.NO_WRAP
                    )
            );
        }
        return "";
    }

    public PublicKey getPublicKey(String base64EncodedString) {
        byte[] byteArray = Base64.decode(
                base64EncodedString.getBytes(),
                Base64.NO_WRAP
        );
        X509EncodedKeySpec spec = new X509EncodedKeySpec(byteArray);
        KeyFactory kf = null;
        PublicKey publicKey= null;
        try {
            kf = KeyFactory.getInstance("RSA");
            publicKey = kf.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public PrivateKey getPrivateKey(String base64EncodedString) {
        byte[] byteArray = Base64.decode(
                base64EncodedString.getBytes(),
                Base64.NO_WRAP
        );
        X509EncodedKeySpec spec = new X509EncodedKeySpec(byteArray);
        KeyFactory kf = null;
        PrivateKey privateKey= null;
        try {
            kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return privateKey;
    }
}
