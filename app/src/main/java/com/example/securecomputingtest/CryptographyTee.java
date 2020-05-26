package com.example.securecomputingtest;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;

class CryptographyTee {

    private static KeyPair keyPairTeeRSA;
    private static KeyPair keyPairTeeECDSA;
    private static String s = "";
    private static String keyProperties = null;

    static byte[] signatureCreatedRSA = new byte[0];
    static byte[] signatureCreatedECDSA = new byte[0];

    static String createKeysRSA(int usePos) throws Exception {

        int keyUsage = 0;
        String keyAlias = "keyTee" + "RSA" + usePos;
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
                        .setKeySize(2048)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                        .setIsStrongBoxBacked(false)
                        .build());
        keyPairTeeRSA = keyPairGenerator.generateKeyPair();

        long stopGen = System.nanoTime();
        long timeGenKey = (stopGen - startGen) / 1000000;
        s = "Generation time in TEE: " + timeGenKey + " ms of Key: " + keyAlias;
        return s;

    }

    static String createKeysAES(int usePos){
        return "not implemented";
    }


    static String createKeysECDSA(int usePos) throws Exception{

        int keyUsage = 0;
        String keyAlias = "keyTee" + "ECDSA" + usePos;

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
                        .setKeySize(256)
                        .setIsStrongBoxBacked(false)
                        .build());

        keyPairTeeECDSA = keyPairGenerator.generateKeyPair();

        long stopGen = System.nanoTime();

        long timeGenKey = (stopGen - startGen) / 1000000;

        s = "Generation time in TEE: " + timeGenKey + " ms of Key: " + keyAlias;

        return s;
    }


    static String createKeysHMAC(int usePos){
        return "not implemented";
    }

    static String useKeysRSA(int messagePos, int useKeyPos) throws Exception {
        /*********************************************************************************************/

        int useKey = 0;
        byte data = (byte) 0;
        boolean valid = false;
        String instanceSign = "";

        if (useKeyPos == 0 || useKeyPos == 1) {
            useKey = 0;
        } else if (useKeyPos == 2 || useKeyPos == 3) {
            useKey = 1;
        }

        String keyAlias = "keyTee" + "RSA" + useKey;


        if (messagePos == 0) {
            data = (byte) 123;
        } else if (messagePos == 1) {
            data = (byte) 123;
        } else if (messagePos == 2) {
            data = (byte) 123;
        }

        instanceSign = "SHA256withRSA";


        /**************** obtaining key *********************************************************************/
        long startGetKey = System.nanoTime();

        // The key pair can also be obtained from the Android Keystore any time as follows:
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
        KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
        KeyInfo keyInfo = null;

        try {
            keyInfo = factory.getKeySpec(privateKey, KeyInfo.class);
        } catch (InvalidKeySpecException e) {
            // Not an Android KeyStore key.
        }
        PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();

        long stopGetKey = System.nanoTime();


        /********** using key **********************************************/
        long start = System.nanoTime();

        if (useKeyPos == 0) {

        } else if (useKeyPos == 1) {

        } else if (useKeyPos == 2) {

            Signature signature = Signature.getInstance(instanceSign);
            signature.initSign(privateKey);

            signature.update(data);
            signatureCreatedRSA = signature.sign();

        } else if (useKeyPos == 3) {

            Signature signature = Signature.getInstance(instanceSign);
            signature.initVerify(publicKey);

            signature.update(data);
            valid = signature.verify(signatureCreatedRSA);

        }

        long stop = System.nanoTime();

        /************* String generation ***********************************************************************/
        //for ms divide by 1000000
        String secureHW = "";

        if (keyInfo.isInsideSecureHardware()) {
            secureHW = "Key is inside secure hardware";
        } else {
            secureHW = "Key is NOT inside secure hardware";
        }

        long timeElapsedGetKey = (stopGetKey - startGetKey) / 1000000;
        long timeSig = (stop - start) / 1000000;


        if (useKeyPos == 0) {

        } else if (useKeyPos == 1) {

        } else if (useKeyPos == 2) {
            s = secureHW + "\n" + "\n"
                    + "Private Key: " + privateKey.toString() + "\n"
                    + "Public Key: " + publicKey.toString() + "\n" + "\n"
                    + "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                    + "Time for signing entry '123': " + timeSig + " ms \n" + "\n"
                    + "Created signature";
        } else if (useKeyPos == 3) {
            s = secureHW + "\n" + "\n"
                    + "Private Key: " + privateKey.toString() + "\n"
                    + "Public Key: " + publicKey.toString() + "\n" + "\n"
                    + "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                    + "Time for verifying entry '123': " + timeSig + " ms \n"
                    + "data is valid: " + valid;
        }
        return s;
    }

    static String useKeysAES(int messagePos, int useKeyPos){
        return "not implemented";
    }

    static String useKeysECDSA(int messagePos, int useKeyPos) throws Exception{
        /*********************************************************************************************/
        int useKey = 0;
        byte data = (byte) 0;
        boolean valid = false;
        String instanceSign = "";

        if (useKeyPos == 0 || useKeyPos == 1) {
            useKey = 0;
        } else if (useKeyPos == 2 || useKeyPos == 3) {
            useKey = 1;
        }

        String keyAlias = "keyTee" + "ECDSA" + useKey;


        if (messagePos == 0) {
            data = (byte) 123;
        } else if (messagePos == 1) {
            data = (byte) 123;
        } else if (messagePos == 2) {
            data = (byte) 123;
        }

        instanceSign = "SHA256withECDSA";


        /**************** obtaining key *********************************************************************/
        long startGetKey = System.nanoTime();

        // The key pair can also be obtained from the Android Keystore any time as follows:
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyAlias, null);
        KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
        KeyInfo keyInfo = null;

        try {
            keyInfo = factory.getKeySpec(privateKey, KeyInfo.class);
        } catch (InvalidKeySpecException e) {
            // Not an Android KeyStore key.
        }
        PublicKey publicKey = keyStore.getCertificate(keyAlias).getPublicKey();

        long stopGetKey = System.nanoTime();

        /********** using key **********************************************/
        long start = System.nanoTime();

        if (useKeyPos == 0) {

        } else if (useKeyPos == 1) {

        } else if (useKeyPos == 2) {

            Signature signature = Signature.getInstance(instanceSign);
            signature.initSign(keyPairTeeECDSA.getPrivate());

            signature.update(data);
            signatureCreatedECDSA = signature.sign();

        } else if (useKeyPos == 3) {

            Signature signature = Signature.getInstance(instanceSign);
            signature.initVerify(keyPairTeeECDSA.getPublic());

            signature.update(data);
            valid = signature.verify(signatureCreatedECDSA);

        }

        long stop = System.nanoTime();

        /************* String generation ***********************************************************************/
        //for ms divide by 1000000
        String secureHW = "";

        if (keyInfo.isInsideSecureHardware()) {
            secureHW = "Key is inside secure hardware";
        } else {
            secureHW = "Key is NOT inside secure hardware";
        }

        long timeElapsedGetKey = (stopGetKey - startGetKey) / 1000000;
        long timeSig = (stop - start) / 1000000;


        if (useKeyPos == 0) {

        } else if (useKeyPos == 1) {

        } else if (useKeyPos == 2) {
            s = secureHW + "\n" + "\n"
                    + "Private Key: " + privateKey.toString() + "\n"
                    + "Public Key: " + publicKey.toString() + "\n" + "\n"
                    + "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                    + "Time for signing entry '123': " + timeSig + " ms \n" + "\n"
                    + "Created signature";
        } else if (useKeyPos == 3) {
            s = secureHW + "\n" + "\n"
                    + "Private Key: " + privateKey.toString() + "\n"
                    + "Public Key: " + publicKey.toString() + "\n" + "\n"
                    + "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                    + "Time for verifying entry '123': " + timeSig + " ms \n"
                    + "data is valid: " + valid;
        }
        return s;
    }

    static String userKeysHMAC(int messagePos, int useKeyPos){
        return "not implemented";
    }
}
