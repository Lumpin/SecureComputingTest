package com.example.securecomputingtest;


import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class CryptographySe {

    private static KeyPair keyPairSeRSA;
    private static KeyPair keyPairSeECDSA;
    private static SecretKey keySeHMAC;
    private static SecretKey keySeAES;
    private static String s = "";
    private static String keyProperties = null;

    static byte[] signatureCreatedRSA = new byte[0];
    static byte[] signatureCreatedECDSA = new byte[0];

    private static byte[] cipherCreatedRSA = new byte[0];
    private static byte[] cipherDecryptedRSA = new byte[0];

    private static byte[] cipherCreatedEC = new byte[0];
    private static byte[] cipherDecryptedEC = new byte[0];


    private static byte[] cipherCreatedAES = new byte[0];
    private static byte[] cipherDecryptedAES = new byte[0];


    private static byte[] macCreated = new byte[0];
    private static byte[] macDecrypted= new byte[0];

    // keygen arrays
    public int keyGenRsaSeEnc[] = new int[10];
    public int keyGenRsaSeSig[] = new int[10];

    public int keyGenAesSeEnc[] = new int[10];

    public int keyGenEcSeEnc[] = new int[10];

    public int keyGenHmacSeEnc[] = new int[10];

    //keyuse arrays
    public int keyUseRsaSeEnc[] = new int[10];
    public int keyUseRsaSeDec[] = new int[10];
    public int keyUseRsaSeSig[] = new int[10];
    public int keyUseRsaSeVer[] = new int[10];

    public int keyUseAesSeEnc[] = new int[10];
    public int keyUseAesSeDec[] = new int[10];

    public int keyUseEcSeEnc[] = new int[10];
    public int keyUseEcSeDec[] = new int[10];

    public int keyUseHmacSeEnc[] = new int[10];
    public int keyUseHmacSeDec[] = new int[10];

    /**
     *
     * @param usePos
     * @return
     * @throws Exception
     */
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

        long timeGenKey = (stopGen - startGen);

        s = "Generation time in SE: " + timeGenKey + " ns of Key: " + keyAlias;

        return s;
    }

    /**
     *
     * @param usePos
     * @return
     * @throws Exception
     */
    public static String createKeysAES(int usePos){

        try {
            String keyAlias = "keySe" + "AES" + usePos;
            int keyUsage = 0;

            if (usePos == 0) {
                keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);

            } else if (usePos == 1) {
                s = "not supported";
            }

            long startGen = System.nanoTime();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(keyAlias, keyUsage)
                            .setKeySize(256)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                            .setIsStrongBoxBacked(true)
                            .build());
            keySeAES = keyGenerator.generateKey();

            long stopGen = System.nanoTime();
            long timeGenKey = (stopGen - startGen);

            s = "Generation time in SE: " + timeGenKey + " ns of Key: " + keyAlias;

            return s;
        }
         catch (Exception e)
        {
            e.printStackTrace();
            return String.valueOf(e);
        }
    }


    /**
     *
     * @param usePos
     * @return
     * @throws Exception
     */
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

        long timeGenKey = (stopGen - startGen);

        s = "Generation time in SE: " + timeGenKey + " ns of Key: " + keyAlias;

        return s;
    }


    /**
     *
     * @param usePos
     * @return
     * @throws Exception
     */
    public static String createKeysHMAC(int usePos) throws Exception{
        String keyAlias = "keySe" + "HMAC" + usePos;
        int keyUsage = 0;

        if (usePos == 0) {
            s = "not supported";
        } else if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long startGen = System.nanoTime();

        KeyGenerator keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore");
        keyGenerator.init(
                new KeyGenParameterSpec.Builder(keyAlias, keyUsage)
                        .setIsStrongBoxBacked(true)
                        .build());
        keySeHMAC = keyGenerator.generateKey();
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySeHMAC);

        long stopGen = System.nanoTime();
        long timeGenKey = (stopGen - startGen);

        s = "Generation time in SE: " + timeGenKey + " ns of Key: " + keyAlias;

        return s;
    }

    public static String useKeysRSA(int useKeyPos) throws Exception{

        try {

            int useKey = 0;
            byte data[] = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};
            boolean valid = false;
            String instance = "";

            System.out.println(data.toString());

            if (useKeyPos == 0 || useKeyPos == 1) {
                useKey = 0;
            } else if (useKeyPos == 2 || useKeyPos == 3) {
                useKey = 1;
            }

            String keyAlias = "keySe" + "RSA" + useKey;

            instance = "SHA256withRSA";

            /********** using key **********************************************/
            long start = System.nanoTime();
            long stop = System.nanoTime();

            if (useKeyPos == 0) {
                start = System.nanoTime();
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(cipher.ENCRYPT_MODE, keyPairSeRSA.getPublic());

                cipherCreatedRSA = cipher.doFinal(data);
                stop = System.nanoTime();

            } else if (useKeyPos == 1) {
                start = System.nanoTime();
                Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher2.init(cipher2.DECRYPT_MODE,keyPairSeRSA.getPrivate());

                cipherDecryptedRSA = cipher2.doFinal(cipherCreatedRSA);
                stop = System.nanoTime();
            } else if (useKeyPos == 2) {
                start = System.nanoTime();
                Signature signature = Signature.getInstance(instance);
                signature.initSign(keyPairSeRSA.getPrivate());

                signature.update(data);
                signatureCreatedRSA = signature.sign();
                stop = System.nanoTime();
            } else if (useKeyPos == 3) {
                start = System.nanoTime();
                Signature signature = Signature.getInstance(instance);
                signature.initVerify(keyPairSeRSA.getPublic());

                signature.update(data);
                valid = signature.verify(signatureCreatedRSA);
                stop = System.nanoTime();
            }


            /************* String generation ***********************************************************************/
            //forns divide by 1000000
            long timeSig = (stop - start);


            if (useKeyPos == 0) {
                s = keyAlias
                        + "Time for enc entry '123': " + timeSig + " ns \n" + "\n"
                        + "Created enc";

            } else if (useKeyPos == 1) {
                s=    keyAlias
                        + "Time for dec entry '123': " + timeSig + " ns \n"
                        + "data is decrypted: ";
            } else if (useKeyPos == 2) {
                s = keyAlias
                        + "Time for signing entry '123': " + timeSig + " ns \n" + "\n"
                        + "Created signature";
            } else if (useKeyPos == 3) {
                s = keyAlias
                        + "Time for verifying entry '123': " + timeSig + " ns \n"
                        + "data is valid: " + valid;
            }
            return s;
        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }
    }

    public static String useKeysAES(int useKeyPos){
        try {
            int useKey = 0;
            byte data[] = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};
            boolean valid = false;

            System.out.println(data.toString());

            if (useKeyPos == 0 || useKeyPos == 1) {
                useKey = 0;
            } else if (useKeyPos == 2 || useKeyPos == 3) {
                useKey = 1;
            }

            String keyAlias = "keySe" + "AES" + useKey;

            long start = System.nanoTime();
            long stop = System.nanoTime();

            if (useKeyPos == 3) {
                start = System.nanoTime();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                cipher.init(cipher.ENCRYPT_MODE,  keySeAES);

                cipherCreatedAES = cipher.doFinal(data);
                stop = System.nanoTime();

            } else if (useKeyPos == 4) {
                start = System.nanoTime();
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                cipher.init(cipher.DECRYPT_MODE, keySeAES);

                cipherDecryptedAES = cipher.doFinal(cipherCreatedAES);
                stop = System.nanoTime();
            }

            //forns divide by 1000000
            long timeSig = (stop - start);


            if (useKeyPos == 0) {
                s =       keyAlias+
                        "Key: " + keySeAES.toString() + "\n"
                        + "Time for enc entry '123': " + timeSig + " ns \n" + "\n"
                        + "Created enc";

            } else if (useKeyPos == 1) {
                s = keyAlias+
                        "Key: " + keySeAES.toString() + "\n"
                        + "Time for dec entry '123': " + timeSig + " ns \n"
                        + "data is decrypted: ";
            } else if (useKeyPos == 2) {
                s = "not supported";
            } else if (useKeyPos == 3) {
                s = "not supported";
            }
            return s;

        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }
    }

    /**
     *
     * @param useKeyPos
     * @return
     * @throws Exception
     */
    public static String useKeysECDSA(int useKeyPos){

        try {

            /*********************************************************************************************/
            int useKey = 0;
            byte data[] = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};
            boolean valid = false;
            String instanceSign = "";

            if (useKeyPos == 0 || useKeyPos == 1) {
                useKey = 0;
            } else if (useKeyPos == 2 || useKeyPos == 3) {
                useKey = 1;
            }

            String keyAlias = "keySe" + "ECDSA" + useKey;

            instanceSign = "SHA256withECDSA";


            /********** using key **********************************************/
            long start = System.nanoTime();

            long stop = System.nanoTime();

            if (useKeyPos == 0) {


            } else if (useKeyPos == 1) {

            } else if (useKeyPos == 2) {
                start = System.nanoTime();
                Signature signature = Signature.getInstance(instanceSign);
                signature.initSign(keyPairSeECDSA.getPrivate());

                signature.update(data);
                signatureCreatedECDSA = signature.sign();
                stop = System.nanoTime();

            } else if (useKeyPos == 3) {
                start = System.nanoTime();
                Signature signature = Signature.getInstance(instanceSign);
                signature.initVerify(keyPairSeECDSA.getPublic());

                signature.update(data);
                valid = signature.verify(signatureCreatedECDSA);
                stop = System.nanoTime();

            }


            /************* String generation ***********************************************************************/
            //forns divide by 1000000
            long timeSig = (stop - start) / 1000000;


            if (useKeyPos == 0) {

            } else if (useKeyPos == 1) {

            } else if (useKeyPos == 2) {
                s = keyAlias
                        + "Time for signing entry '123': " + timeSig + "ns \n" + "\n"
                        + "Created signature";
            } else if (useKeyPos == 3) {
                s = keyAlias
                        + "Time for verifying entry '123': " + timeSig + "ns \n"
                        + "data is valid: " + valid;
            }
            return s;
        } catch (Exception e) {

            e.printStackTrace();
            return "Error";
        }
    }

    public static String userKeysHMAC(int useKeyPos){
        try {

            /*********************************************************************************************/
            int useKey = 0;
            byte data[] = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};
            boolean valid = false;

            if (useKeyPos == 0 || useKeyPos == 1) {
                useKey = 0;
            } else if (useKeyPos == 2 || useKeyPos == 3) {
                useKey = 1;
            }

            String keyAlias = "keyTee" + "HMAC" + useKey;



            long start = System.nanoTime();
            long stop = System.nanoTime();

            if (useKeyPos == 0) {


            } else if (useKeyPos == 1) {

            } else if (useKeyPos == 2) {
                start = System.nanoTime();
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(keySeHMAC);


                macCreated = mac.doFinal(data);
                stop = System.nanoTime();

            } else if (useKeyPos == 3) {
                start = System.nanoTime();
                Mac mac = Mac.getInstance("HmacSHA256");

                mac.init(keySeHMAC);
                macDecrypted = mac.doFinal(macCreated);
                stop = System.nanoTime();
            }


            /************* String generation ***********************************************************************/
            //forns divide by 1000000
            long timeSig = (stop - start) / 1000000;


            if (useKeyPos == 0) {

            } else if (useKeyPos == 1) {

            } else if (useKeyPos == 2) {
                s = keyAlias
                        + "Time for signing entry '123': " + timeSig + "ns \n" + "\n"
                        + "Created mac";
            } else if (useKeyPos == 3) {
                s = keyAlias
                        + "Time for verifying entry '123': " + timeSig + "ns \n"
                        + "data is valid: " ;
            }
            return s;
        } catch (Exception e) {

            e.printStackTrace();
            return "Error";
        }

    }
}
