package com.example.securecomputingtest;


import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class CryptographySe {

    private static KeyPair keyPairSeRSA;
    private static KeyPair keyPairSeECDSA;
    private static String s = "";
    private static String keyProperties = null;

    static byte[] signatureCreatedRSA = new byte[0];
    static byte[] signatureCreatedECDSA = new byte[0];

    public static String createKeysRSA(int usePos) throws Exception{
        int keyUsage = 0;
        String keyAlias = "keySe" + "RSA" + usePos;

        keyProperties = KeyProperties.KEY_ALGORITHM_RSA;

        if (usePos == 0) {
            keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        } else if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long startGen = System.nanoTime();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                keyProperties, "AndroidKeyStore");

        keyPairGenerator.initialize(
                new KeyGenParameterSpec.Builder(
                        keyAlias,
                        keyUsage).setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(
                                KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setIsStrongBoxBacked(true)
                        .build());

        keyPairSeRSA = keyPairGenerator.generateKeyPair();

        long stopGen = System.nanoTime();

        long timeGenKey = (stopGen - startGen) / 1000000;

        s = "Generation time in SE: " + timeGenKey + " ms of Key: " + keyAlias;

        return s;
    }



    public static String createKeysAES(int usePos){
        return "not implemented";
    }


    public static String createKeysECDSA(int usePos) throws Exception{
        int keyUsage = 0;
        String keyAlias = "keySe" + "ECDSA" + usePos;

        keyProperties = KeyProperties.KEY_ALGORITHM_EC;

        if (usePos == 0) {
            keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        } else if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long startGen = System.nanoTime();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                keyProperties, "AndroidKeyStore");

        keyPairGenerator.initialize(
                new KeyGenParameterSpec.Builder(
                        keyAlias,
                        keyUsage).setDigests(KeyProperties.DIGEST_SHA256,
                        KeyProperties.DIGEST_SHA512)
                        .setIsStrongBoxBacked(true)
                        .build());

        keyPairSeECDSA = keyPairGenerator.generateKeyPair();

        long stopGen = System.nanoTime();

        long timeGenKey = (stopGen - startGen) / 1000000;

        s = "Generation time in SE: " + timeGenKey + " ms of Key: " + keyAlias;

        return s;
    }


    public static String createKeysHMAC(int usePos){
        return "not implemented";
    }

    public static String useKeysRSA(int messagePos, int useKeyPos) throws Exception{
        return "not implemented";
    }

    public static String useKeysAES(int messagePos, int useKeyPos){
        return "not implemented";
    }

    public static String useKeysECDSA(int messagePos, int useKeyPos) throws Exception{
        return "not implemented";
    }

    public static String userKeysHMAC(int messagePos, int useKeyPos){
        return "not implemented";
    }
}
