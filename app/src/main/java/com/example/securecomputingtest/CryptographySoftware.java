package com.example.securecomputingtest;


import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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
    public static long[] keyGenRsaSwEnc = new long[Parameters.RUNS];
    public static long[] keyGenRsaSwSig = new long[Parameters.RUNS];

    public static long[] keyGenAesSwEnc = new long[Parameters.RUNS];

    public static long[] keyGenEcSwEnc = new long[Parameters.RUNS];

    public static long[] keyGenHmacSwEnc = new long[Parameters.RUNS];

    //keyuse arrays
    public static long[] keyUseRsaSwEnc = new long[Parameters.RUNS];
    public static long[] keyUseRsaSwDec = new long[Parameters.RUNS];
    public static long[] keyUseRsaSwSig = new long[Parameters.RUNS];
    public static long[] keyUseRsaSwVer = new long[Parameters.RUNS];

    public static long[] keyUseAesSwEnc = new long[Parameters.RUNS];
    public static long[] keyUseAesSwDec = new long[Parameters.RUNS];

    public static long[] keyUseEcSwEnc = new long[Parameters.RUNS];
    public static long[] keyUseEcSwDec = new long[Parameters.RUNS];

    public static long[] keyUseHmacSwEnc = new long[Parameters.RUNS];
    public static long[] keyUseHmacSwDec = new long[Parameters.RUNS];


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
        for (int i = 0; i < Parameters.RUNS; i++) {

            long startGen = System.nanoTime();

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            keyPairGenerator.initialize(new KeyGenParameterSpec.Builder(
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
            timeGenKey = (stopGen - startGen)/Parameters.MEASURETIME;


            if (usePos == 0) {
                keyGenRsaSwEnc[i] = timeGenKey;
            } else if (usePos == 1) {
                keyGenRsaSwSig[i] = timeGenKey;
            }

            Thread.sleep(Parameters.SLEEPTIME);
        }
        if (usePos == 0) {
            return keyGenRsaSwEnc;
        } else if (usePos == 1) {
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

        for (int i = 0; i < Parameters.RUNS; i++) {
            long startGen = System.nanoTime();
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            keySwAES = keyGenerator.generateKey();

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen)/Parameters.MEASURETIME;

            keyGenAesSwEnc[i] = timeGenKey;

            Thread.sleep(Parameters.SLEEPTIME);
        }

        return keyGenAesSwEnc;
    }


    static long[] createKeysECDSA(int usePos) throws Exception {

        int keyUsage = 0;
        String keyAlias = "keySw" + "ECDSA" + usePos;

        if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        keyProperties = KeyProperties.KEY_ALGORITHM_EC;

        long timeGenKey;
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);

        for (int i = 0; i < Parameters.RUNS; i++) {
            long startGen = System.nanoTime();

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyProperties);
            ECGenParameterSpec namedParamSpec = new ECGenParameterSpec("secp256k1");
            keyPairGenerator.initialize(namedParamSpec);
            /*
            //see https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec - but does not work anymore apparently
            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            keyAlias,
                            keyUsage).setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256,
                                    KeyProperties.DIGEST_SHA512)
                          //  .setKeySize(256)
                            .build());
               */

            keyPairSwECDSA = keyPairGenerator.generateKeyPair();

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen)/Parameters.MEASURETIME;

            keyGenEcSwEnc[i] = timeGenKey;

            Thread.sleep(Parameters.SLEEPTIME);
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
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);

        for (int i = 0; i < Parameters.RUNS; i++) {

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
            timeGenKey = (stopGen - startGen)/Parameters.MEASURETIME;

            keyGenHmacSwEnc[i] = timeGenKey;

            Thread.sleep(Parameters.SLEEPTIME);
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
                for (int i = 0; i < Parameters.RUNS; i++) {

                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, keyPairSwRSA.getPublic());

                    cipherCreatedRSA = cipher.doFinal(data);
                    stop = System.nanoTime();

                    keyUseRsaSwEnc[i] = (stop - start)/Parameters.MEASURETIME;
                    Thread.sleep(Parameters.SLEEPTIME);
                }
                return keyUseRsaSwEnc;
            } else if (useKeyPos == 1) {
                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher2.init(Cipher.DECRYPT_MODE, keyPairSwRSA.getPrivate());

                    cipher2.doFinal(cipherCreatedRSA);
                    stop = System.nanoTime();
                    keyUseRsaSwDec[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
                }
                return keyUseRsaSwDec;
            } else if (useKeyPos == 2) {
                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instance);
                    signature.initSign(keyPairSwRSA.getPrivate());

                    signature.update(data);
                    signatureCreatedRSA = signature.sign();
                    stop = System.nanoTime();
                    keyUseRsaSwSig[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
                }
                return keyUseRsaSwSig;

            } else if (useKeyPos == 3) {
                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instance);
                    signature.initVerify(keyPairSwRSA.getPublic());

                    signature.update(data);
                    signature.verify(signatureCreatedRSA);
                    stop = System.nanoTime();
                    keyUseRsaSwVer[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
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

            byte[] iv = new byte[16];
            SecureRandom random;
            random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            SecretKeySpec keySpec = new SecretKeySpec(keySwAES.getEncoded(), "AES");

            long start;
            long stop;

            if (useKeyPos == 0) {

                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

                    cipherCreatedAES = cipher.doFinal(data);
                    stop = System.nanoTime();

                    keyUseAesSwEnc[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
                }
                return keyUseAesSwEnc;

            } else if (useKeyPos == 1) {

                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

                    cipher.doFinal(cipherCreatedAES);
                    stop = System.nanoTime();

                    keyUseAesSwDec[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
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
                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instanceSign);
                    signature.initSign(keyPairSwECDSA.getPrivate());

                    signature.update(data);
                    signatureCreatedECDSA = signature.sign();
                    stop = System.nanoTime();

                    keyUseEcSwEnc[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
                }

                return keyUseEcSwEnc;

            } else if (useKeyPos == 3) {
                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instanceSign);
                    signature.initVerify(keyPairSwECDSA.getPublic());

                    signature.update(data);
                    signature.verify(signatureCreatedECDSA);
                    stop = System.nanoTime();

                    keyUseEcSwDec[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
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

                for (int i = 0; i < Parameters.RUNS; i++) {

                    start = System.nanoTime();
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(keySwHMAC);
                    macCreated = mac.doFinal(data);
                    stop = System.nanoTime();

                    keyUseHmacSwEnc[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
                }
                return keyUseHmacSwEnc;

            } else if (useKeyPos == 3) {

                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Mac mac = Mac.getInstance("HmacSHA256");

                    mac.init(keySwHMAC);
                    mac.doFinal(macCreated);
                    stop = System.nanoTime();

                    keyUseHmacSwDec[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
                }
                return keyUseHmacSwDec;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
