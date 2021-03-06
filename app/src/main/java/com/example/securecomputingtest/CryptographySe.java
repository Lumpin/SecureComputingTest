package com.example.securecomputingtest;


import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


/*
class for key storage in embedded SE

 */
public class CryptographySe {

    private static KeyPair keyPairSeRSA;
    private static KeyPair keyPairSeECDSA;
    private static SecretKey keySeHMAC;
    private static SecretKey keySeAES;
    private static String keyProperties = null;

    private static byte[] signatureCreatedRSA = new byte[0];
    private static byte[] signatureCreatedECDSA = new byte[0];

    private static byte[] cipherCreatedRSA = new byte[0];

    private static byte[] cipherCreatedAES = new byte[0];

    private static byte[] macCreated = new byte[0];

    // keygen arrays
    public static long[] keyGenRsaSeEnc = new long[Parameters.RUNS];
    public static long[] keyGenRsaSeSig = new long[Parameters.RUNS];

    public static long[] keyGenAesSeEnc = new long[Parameters.RUNS];

    public static long[] keyGenEcSeEnc = new long[Parameters.RUNS];

    public static long[] keyGenHmacSe = new long[Parameters.RUNS];

    //keyuse arrays
    public static long[] keyUseRsaSeEnc = new long[Parameters.RUNS];
    public static long[] keyUseRsaSeDec = new long[Parameters.RUNS];
    public static long[] keyUseRsaSeSig = new long[Parameters.RUNS];
    public static long[] keyUseRsaSeVer = new long[Parameters.RUNS];

    public static long[] keyUseAesSeEnc = new long[Parameters.RUNS];
    public static long[] keyUseAesSeDec = new long[Parameters.RUNS];

    public static long[] keyUseEcSeSig = new long[Parameters.RUNS];
    public static long[] keyUseEcSeVer = new long[Parameters.RUNS];

    public static long[] keyUseHmacSeSig = new long[Parameters.RUNS];
    public static long[] keyUseHmacSeVer = new long[Parameters.RUNS];

    /*
               creation of RSA keys
    */
    static long[] createKeysRSA(int usePos) throws Exception {

        int keyUsage = 0;
        String keyAlias = "keySe" + "RSA" + usePos;
        keyProperties = KeyProperties.KEY_ALGORITHM_RSA;

        if (usePos == 0) {
            keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        } else if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long timeGenKey;
        for (int i = 0; i < Parameters.RUNS; i++) {

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
                            .setIsStrongBoxBacked(true)
                            .build());
            keyPairSeRSA = keyPairGenerator.generateKeyPair();

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen)/Parameters.MEASURETIME;

            PrivateKey key = keyPairSeRSA.getPrivate();
            KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo;
            try {
                keyInfo = factory.getKeySpec(key, KeyInfo.class);
                System.out.println("SE" + keyInfo.isInsideSecureHardware());
            } catch (InvalidKeySpecException e) {
                // Not an Android KeyStore key.
            }

            if (usePos == 0) {
                keyGenRsaSeEnc[i] = timeGenKey;
            } else if (usePos == 1) {
                keyGenRsaSeSig[i] = timeGenKey;
            }

            Thread.sleep(Parameters.SLEEPTIME);
        }
        if (usePos == 0) {
            BenchmarkingResults.storeResults(keyGenRsaSeEnc, keyAlias);
            return keyGenRsaSeEnc;
        } else if (usePos == 1) {
            BenchmarkingResults.storeResults(keyGenRsaSeSig, keyAlias);
            return keyGenRsaSeSig;
        }
        return null;
    }

    /*
               creation of AES keys
    */
    static long[] createKeysAES(int usePos) throws Exception {

        String keyAlias = "keySe" + "AES" + usePos;
        int keyUsage = 0;

        if (usePos == 0) {
            keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);

        }

        long timeGenKey;

        for (int i = 0; i < Parameters.RUNS; i++) {
            long startGen = System.nanoTime();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(keyAlias, keyUsage)
                            .setKeySize(256)
                            .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                            .setRandomizedEncryptionRequired(false)
                            .setIsStrongBoxBacked(true)
                            .build());
            keySeAES = keyGenerator.generateKey();

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen)/Parameters.MEASURETIME;

            keyGenAesSeEnc[i] = timeGenKey;
            Thread.sleep(Parameters.SLEEPTIME);
        }

        BenchmarkingResults.storeResults(keyGenAesSeEnc, keyAlias);
        return keyGenAesSeEnc;
    }

    /*
               creation of ECDSA keys
    */
    static long[] createKeysECDSA(int usePos) throws Exception {

        int keyUsage = 0;
        String keyAlias = "keySe" + "ECDSA" + usePos;

        keyProperties = KeyProperties.KEY_ALGORITHM_EC;

        if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long timeGenKey;

        for (int i = 0; i < Parameters.RUNS; i++) {
            long startGen = System.nanoTime();

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    keyProperties, "AndroidKeyStore");

            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            keyAlias,
                            keyUsage).setDigests(KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA512)
                            .setKeySize(256)
                            .setIsStrongBoxBacked(true)
                            .build());

            keyPairSeECDSA = keyPairGenerator.generateKeyPair();
            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen)/Parameters.MEASURETIME;

            keyGenEcSeEnc[i] = timeGenKey;
            Thread.sleep(Parameters.SLEEPTIME);

        }
        BenchmarkingResults.storeResults(keyGenEcSeEnc, keyAlias);
        return keyGenEcSeEnc;

    }

    /*
               creation of HMAC keys
    */
    static long[] createKeysHMAC(int usePos) throws Exception {

        String keyAlias = "keySe" + "HMAC" + usePos;
        int keyUsage = 0;

        if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long timeGenKey;
        for (int i = 0; i < Parameters.RUNS; i++) {

            long startGen = System.nanoTime();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore");
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(keyAlias, keyUsage)
                            .setIsStrongBoxBacked(true)
                            .build());
            keySeHMAC = keyGenerator.generateKey();

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen)/Parameters.MEASURETIME;

            keyGenHmacSe[i] = timeGenKey;
            Thread.sleep(Parameters.SLEEPTIME);
        }

        BenchmarkingResults.storeResults(keyGenHmacSe, keyAlias);
        return keyGenHmacSe;
    }

    /*
               usage of RSA keys
    */
    static long[] useKeysRSA(int useKeyPos) {

        try {

            byte[] data = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};

            String instance = "SHA256withRSA";

            long start;
            long stop;

            if (useKeyPos == 0) {
                for (int i = 0; i < Parameters.RUNS; i++) {

                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, keyPairSeRSA.getPublic());

                    cipherCreatedRSA = cipher.doFinal(data);
                    stop = System.nanoTime();

                    keyUseRsaSeEnc[i] = (stop - start)/Parameters.MEASURETIME;
                    Thread.sleep(Parameters.SLEEPTIME);

                }

                BenchmarkingResults.storeResults(keyUseRsaSeEnc, "keyUseRsaSeEnc");
                return keyUseRsaSeEnc;
            } else if (useKeyPos == 1) {
                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher2.init(Cipher.DECRYPT_MODE, keyPairSeRSA.getPrivate());

                    cipher2.doFinal(cipherCreatedRSA);
                    stop = System.nanoTime();
                    keyUseRsaSeDec[i] = (stop - start)/Parameters.MEASURETIME;
                    Thread.sleep(Parameters.SLEEPTIME);

                }

                BenchmarkingResults.storeResults(keyUseRsaSeDec, "keyUseRsaSeDec");
                return keyUseRsaSeDec;
            } else if (useKeyPos == 2) {
                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instance);
                    signature.initSign(keyPairSeRSA.getPrivate());

                    signature.update(data);
                    signatureCreatedRSA = signature.sign();
                    stop = System.nanoTime();
                    keyUseRsaSeSig[i] = (stop - start)/Parameters.MEASURETIME;
                    Thread.sleep(Parameters.SLEEPTIME);

                }

                BenchmarkingResults.storeResults(keyUseRsaSeSig, "keyUseRsaSeSig");
                return keyUseRsaSeSig;

            } else if (useKeyPos == 3) {
                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instance);
                    signature.initVerify(keyPairSeRSA.getPublic());

                    signature.update(data);
                    signature.verify(signatureCreatedRSA);
                    stop = System.nanoTime();
                    keyUseRsaSeVer[i] = (stop - start)/Parameters.MEASURETIME;
                    Thread.sleep(Parameters.SLEEPTIME);

                }

                BenchmarkingResults.storeResults(keyUseRsaSeVer, "keyUseRsaSeVer");
                return keyUseRsaSeVer;
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /*
               usage of AES keys
    */
    static long[] useKeysAES(int useKeyPos) {
        try {

            byte[] data = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};


            long start;
            long stop;

            byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            if (useKeyPos == 0) {

                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, keySeAES, ivspec);

                    cipherCreatedAES = cipher.doFinal(data);
                    stop = System.nanoTime();

                    keyUseAesSeEnc[i] = (stop - start)/Parameters.MEASURETIME;
                    Thread.sleep(Parameters.SLEEPTIME);
                }

                BenchmarkingResults.storeResults(keyUseAesSeEnc, "keyUseAesSeEnc");
                return keyUseAesSeEnc;

            } else if (useKeyPos == 1) {

                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    cipher.init(Cipher.DECRYPT_MODE, keySeAES, ivspec);

                    cipher.doFinal(cipherCreatedAES);
                    stop = System.nanoTime();

                    keyUseAesSeDec[i] = (stop - start)/Parameters.MEASURETIME;
                    Thread.sleep(Parameters.SLEEPTIME);
                }

                BenchmarkingResults.storeResults(keyUseAesSeDec, "keyUseAesSeDec");
                return keyUseAesSeDec;

            }

        } catch (Exception e) {
            e.printStackTrace();

        }
        return null;
    }

    /*
           usage of ECDSA keys
*/
    static long[] useKeysECDSA(int useKeyPos) {
        try {

            byte[] data = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};

            String instanceSign = "SHA256withECDSA";

            long start;
            long stop;

            if (useKeyPos == 2) {
                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instanceSign);
                    signature.initSign(keyPairSeECDSA.getPrivate());

                    signature.update(data);
                    signatureCreatedECDSA = signature.sign();
                    stop = System.nanoTime();

                    keyUseEcSeSig[i] = (stop - start)/Parameters.MEASURETIME;
                    Thread.sleep(Parameters.SLEEPTIME);
                }
                BenchmarkingResults.storeResults(keyUseEcSeSig, "keyUseEcSeSig");
                return keyUseEcSeSig;

            } else if (useKeyPos == 3) {
                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instanceSign);
                    signature.initVerify(keyPairSeECDSA.getPublic());

                    signature.update(data);
                    signature.verify(signatureCreatedECDSA);
                    stop = System.nanoTime();

                    keyUseEcSeVer[i] = (stop - start)/Parameters.MEASURETIME;
                    Thread.sleep(Parameters.SLEEPTIME);
                }
                BenchmarkingResults.storeResults(keyUseEcSeVer, "keyUseEcSeVer");
                return keyUseEcSeVer;
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

    }

    /*
           usage of HMAC keys
    */
    static long[] useKeysHMAC(int useKeyPos) {
        try {

            byte[] data = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};


            long start;
            long stop;

            if (useKeyPos == 2) {

                for (int i = 0; i < Parameters.RUNS; i++) {

                    start = System.nanoTime();
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(keySeHMAC);
                    macCreated = mac.doFinal(data);
                    stop = System.nanoTime();

                    keyUseHmacSeSig[i] = (stop - start)/Parameters.MEASURETIME;
                    Thread.sleep(Parameters.SLEEPTIME);
                }
                BenchmarkingResults.storeResults(keyUseHmacSeSig, "keyUseHmacSeSig");
                return keyUseHmacSeSig;

            } else if (useKeyPos == 3) {

                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Mac mac = Mac.getInstance("HmacSHA256");

                    mac.init(keySeHMAC);
                    mac.doFinal(macCreated);
                    stop = System.nanoTime();

                    keyUseHmacSeVer[i] = (stop - start)/Parameters.MEASURETIME;
                    Thread.sleep(Parameters.SLEEPTIME);
                }
                BenchmarkingResults.storeResults(keyUseHmacSeVer, "keyUseHmacSeVer");
                return keyUseHmacSeVer;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
