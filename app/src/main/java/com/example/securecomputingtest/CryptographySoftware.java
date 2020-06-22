package com.example.securecomputingtest;


import android.content.Context;
import android.net.wifi.aware.SubscribeConfig;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

class CryptographySoftware {

    private static KeyPair keyPairSwRSA;
    private static KeyPair keyPairSwECDSA;
    private static SecretKey keySwHMAC;
    private static SecretKey keySwAES;
    private static String keyProperties = null;

    private static byte[] signatureCreatedRSA = new byte[0];
    private static byte[] signatureCreatedECDSA = new byte[0];

    private static byte[] cipherCreatedRSA = new byte[0];

    private static byte[] cipherCreatedAES = new byte[0];

    private static byte[] macCreated = new byte[0];

    // keygen arrays
    public static long[] keyGenRsaSwEnc = new long[10];
    public static long[] keyGenRsaSwSig = new long[10];

    public static long[] keyGenAesSwEnc = new long[10];

    public static long[] keyGenEcSwEnc = new long[10];

    public static long[] keyGenHmacSwEnc = new long[10];

    //keyuse arrays
    public static long[] keyUseRsaSwEnc = new long[10];
    public static long[] keyUseRsaSwDec = new long[10];
    public static long[] keyUseRsaSwSig = new long[10];
    public static long[] keyUseRsaSwVer = new long[10];

    public static long[] keyUseAesSwEnc = new long[10];
    public static long[] keyUseAesSwDec = new long[10];

    public static long[] keyUseEcSwEnc = new long[10];
    public static long[] keyUseEcSwDec = new long[10];

    public static long[] keyUseHmacSwEnc = new long[10];
    public static long[] keyUseHmacSwDec = new long[10];


    static long[] createKeysRSA(int usePos) throws Exception {


        int keyUsage = 0;
        String keyAlias = "keySw" + "RSA" + usePos;
        keyProperties = KeyProperties.KEY_ALGORITHM_RSA;

        if (usePos == 0) {
            keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        } else if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long timeGenKey;
        for (int i = 0; i < 10; i++) {

            long startGen = System.nanoTime();

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            keyPairGenerator.initialize( new KeyGenParameterSpec.Builder(
                    keyAlias,
                    keyUsage).setDigests(KeyProperties.DIGEST_SHA256,
                    KeyProperties.DIGEST_SHA512)
                    .setEncryptionPaddings(
                            KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                    .setKeySize(2048)
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                    .build());

            keyPairSwRSA = keyPairGenerator.generateKeyPair();

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen);

         if (usePos == 0) {
                keyGenRsaSwEnc[i] = timeGenKey;
            } else if (usePos == 1) {
                keyGenRsaSwSig[i] = timeGenKey;
            }
        }
        if (usePos == 0) {
            BenchmarkingResults.storeResults(keyGenRsaSwEnc, "Generation" + keyAlias);
            return keyGenRsaSwEnc;
        } else if (usePos == 1) {
            BenchmarkingResults.storeResults(keyGenRsaSwSig, "Generation" + keyAlias);
            return keyGenRsaSwSig;
        }
        return null;
    }


    static long[] createKeysAES(int usePos) throws Exception {

        String keyAlias = "keySw" + "AES" + usePos;
        int keyUsage = 0;

        if (usePos == 0) {
            keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);

        }

        long timeGenKey;

        for (int i = 0; i < 10; i++) {
            long startGen = System.nanoTime();
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(new KeyGenParameterSpec.Builder(keyAlias, keyUsage)
                    .setKeySize(256)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keySwAES = keyGenerator.generateKey();

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen);

            keyGenAesSwEnc[i] = timeGenKey;
        }

        return keyGenAesSwEnc;
    }


    static long[] createKeysECDSA(int usePos) throws Exception {

        int keyUsage = 0;
        String keyAlias = "keySw" + "ECDSA" + usePos;

        keyProperties = KeyProperties.KEY_ALGORITHM_EC;

        if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long timeGenKey;

        for (int i = 0; i < 10; i++) {
            long startGen = System.nanoTime();

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyProperties);

            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            keyAlias,
                            keyUsage).setDigests(KeyProperties.DIGEST_SHA256,
                            KeyProperties.DIGEST_SHA512)
                            .setKeySize(256)
                            .build());

            keyPairSwECDSA = keyPairGenerator.generateKeyPair();
            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen);

            keyGenEcSwEnc[i] = timeGenKey;

        }

        return keyGenEcSwEnc;

    }


    static long[] createKeysHMAC(int usePos) throws Exception {

        String keyAlias = "keySw" + "HMAC" + usePos;
        int keyUsage = 0;

        if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long timeGenKey;
        for (int i = 0; i < 10; i++) {

            long startGen = System.nanoTime();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_HMAC_SHA256);
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(keyAlias, keyUsage)
                            .build());
            keySwHMAC = keyGenerator.generateKey();
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keySwHMAC);

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen);

            keyGenHmacSwEnc[i] = timeGenKey;
        }

        return keyGenHmacSwEnc;
    }


    static long[] useKeysRSA(int useKeyPos) {

        try {

            byte[] data = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};

            String instance = "SHA256withRSA";

            long start;
            long stop = System.nanoTime();

            if (useKeyPos == 0) {
                for (int i = 0; i < 10; i++) {

                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, keyPairSwRSA.getPublic());

                    cipherCreatedRSA = cipher.doFinal(data);
                    stop = System.nanoTime();

                    keyUseRsaSwEnc[i] = (stop - start);

                }
                return keyUseRsaSwEnc;
            } else if (useKeyPos == 1) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher2.init(Cipher.DECRYPT_MODE, keyPairSwRSA.getPrivate());

                    cipher2.doFinal(cipherCreatedRSA);
                    stop = System.nanoTime();
                    keyUseRsaSwDec[i] = (stop - start);

                }
                return keyUseRsaSwDec;
            } else if (useKeyPos == 2) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instance);
                    signature.initSign(keyPairSwRSA.getPrivate());

                    signature.update(data);
                    signatureCreatedRSA = signature.sign();
                    keyUseRsaSwSig[i] = (stop - start);

                }
                return keyUseRsaSwSig;

            } else if (useKeyPos == 3) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instance);
                    signature.initVerify(keyPairSwRSA.getPublic());

                    signature.update(data);
                    signature.verify(signatureCreatedRSA);
                    stop = System.nanoTime();
                    keyUseRsaSwVer[i] = (stop - start);

                }
                return keyUseRsaSwVer;
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    static long[] useKeysAES(int useKeyPos) {
        try {

            byte[] data = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};


            long start;
            long stop;

            if (useKeyPos == 3) {

                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, keySwAES);

                    cipherCreatedAES = cipher.doFinal(data);
                    stop = System.nanoTime();

                    keyUseAesSwEnc[i] = (stop - start);
                }
                return keyUseAesSwEnc;

            } else if (useKeyPos == 4) {

                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    cipher.init(Cipher.DECRYPT_MODE, keySwAES);

                    cipher.doFinal(cipherCreatedAES);
                    stop = System.nanoTime();

                    keyUseAesSwDec[i] = (stop - start);
                }
                return keyUseAesSwDec;

            }

        } catch (Exception e) {
            e.printStackTrace();

        }
        return null;
    }

    static long[] useKeysECDSA(int useKeyPos) {
        try {

            byte[] data = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};

            String instanceSign = "SHA256withECDSA";

            long start;
            long stop;

            if (useKeyPos == 2) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instanceSign);
                    signature.initSign(keyPairSwECDSA.getPrivate());

                    signature.update(data);
                    signatureCreatedECDSA = signature.sign();
                    stop = System.nanoTime();

                    keyUseEcSwEnc[i] = (stop - start);
                }

                return keyUseEcSwEnc;

            } else if (useKeyPos == 3) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instanceSign);
                    signature.initVerify(keyPairSwECDSA.getPublic());

                    signature.update(data);
                    signature.verify(signatureCreatedECDSA);
                    stop = System.nanoTime();

                    keyUseEcSwDec[i] = (stop - start);
                }
                return keyUseEcSwDec;
            }


        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;

    }

    static long[] userKeysHMAC(int useKeyPos) {
        try {

            byte[] data = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};


            long start;
            long stop;

            if (useKeyPos == 2) {

                for (int i = 0; i < 10; i++) {

                    start = System.nanoTime();
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(keySwHMAC);
                    macCreated = mac.doFinal(data);
                    stop = System.nanoTime();

                    keyUseHmacSwEnc[i] = (stop - start);
                }
                return keyUseHmacSwEnc;

            } else if (useKeyPos == 3) {

                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Mac mac = Mac.getInstance("HmacSHA256");

                    mac.init(keySwHMAC);
                    mac.doFinal(macCreated);
                    stop = System.nanoTime();

                    keyUseHmacSwDec[i] = (stop - start);
                }
                return keyUseHmacSwDec;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
