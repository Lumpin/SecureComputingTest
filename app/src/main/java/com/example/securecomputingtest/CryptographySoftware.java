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

/*
Class for software-only keys storage
 */
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

    public static long[] keyGenHmacSw = new long[Parameters.RUNS];

    //keyuse arrays
    public static long[] keyUseRsaSwEnc = new long[Parameters.RUNS];
    public static long[] keyUseRsaSwDec = new long[Parameters.RUNS];
    public static long[] keyUseRsaSwSig = new long[Parameters.RUNS];
    public static long[] keyUseRsaSwVer = new long[Parameters.RUNS];

    public static long[] keyUseAesSwEnc = new long[Parameters.RUNS];
    public static long[] keyUseAesSwDec = new long[Parameters.RUNS];

    public static long[] keyUseEcSwSig = new long[Parameters.RUNS];
    public static long[] keyUseEcSwVer = new long[Parameters.RUNS];

    public static long[] keyUseHmacSwSig = new long[Parameters.RUNS];
    public static long[] keyUseHmacSwVer = new long[Parameters.RUNS];

/*
create RSA keypair
usePos = 0 - sets keyusage to encryption/decryption
usePos = 1 - sets keyusage to sign/verify

 */
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


            Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
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
            BenchmarkingResults.storeResults(keyGenRsaSwEnc, keyAlias);
            return keyGenRsaSwEnc;
        } else if (usePos == 1) {
            BenchmarkingResults.storeResults(keyGenRsaSwSig, keyAlias);
            return keyGenRsaSwSig;
        }
        return null;
    }

    /*
    create AES key
    usePos = 0 - sets keyusage to encryption/decryption

     */
    static long[] createKeysAES(int usePos) throws Exception {

        String keyAlias = "keySw" + "AES" + usePos;
        int keyUsage = 0;

        if (usePos == 0) {
            keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);

        }
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
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
        BenchmarkingResults.storeResults(keyGenAesSwEnc, keyAlias);
        return keyGenAesSwEnc;
    }

    /*
    create ECDSA keypair
    usePos = 0 - sets keyusage to encryption/decryption
    usePos = 1 - sets keyusage to sign/verify

     */
    static long[] createKeysECDSA(int usePos) throws Exception {

        int keyUsage = 0;
        String keyAlias = "keySw" + "ECDSA" + usePos;

        if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        keyProperties = KeyProperties.KEY_ALGORITHM_EC;

        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
        long timeGenKey;

        for (int i = 0; i < Parameters.RUNS; i++) {
            long startGen = System.nanoTime();

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyProperties);
            ECGenParameterSpec namedParamSpec = new ECGenParameterSpec("secp256k1");
            keyPairGenerator.initialize(namedParamSpec);

            keyPairSwECDSA = keyPairGenerator.generateKeyPair();

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen)/Parameters.MEASURETIME;

            keyGenEcSwEnc[i] = timeGenKey;

            Thread.sleep(Parameters.SLEEPTIME);
        }
        BenchmarkingResults.storeResults(keyGenEcSwEnc, keyAlias);
        return keyGenEcSwEnc;

    }

    /*
    create HMAC key
    usePos = 1 - sets keyusage to sign/verify

     */
    static long[] createKeysHMAC(int usePos) throws Exception {

        String keyAlias = "keySw" + "HMAC" + usePos;
        int keyUsage = 0;

        if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        Security.insertProviderAt(
                new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
        long timeGenKey;

        for (int i = 0; i < Parameters.RUNS; i++) {

            long startGen = System.nanoTime();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_HMAC_SHA256);
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(keyAlias, keyUsage)
                            .build());
            keySwHMAC = keyGenerator.generateKey();

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen)/Parameters.MEASURETIME;

            keyGenHmacSw[i] = timeGenKey;
            Thread.sleep(Parameters.SLEEPTIME);
        }
        BenchmarkingResults.storeResults(keyGenHmacSw, keyAlias);
        return keyGenHmacSw;
    }

/*
    usage of RSA keys
 */
    static long[] useKeysRSA(int useKeyPos) {

        try {

            //hard coded message
            byte[] data = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};

            String instance = "SHA256withRSA";

            long start;
            long stop;

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
                BenchmarkingResults.storeResults(keyUseRsaSwEnc, "keyUseRsaSwEnc");
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
                BenchmarkingResults.storeResults(keyUseRsaSwDec, "keyUseRsaSwDec");
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
                BenchmarkingResults.storeResults(keyUseRsaSwSig, "keyUseRsaSwSig");
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
                BenchmarkingResults.storeResults(keyUseRsaSwVer, "keyUseRsaSwVer");
                return keyUseRsaSwVer;
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
                BenchmarkingResults.storeResults(keyUseAesSwEnc, "keyUseAesSwEnc");
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
                BenchmarkingResults.storeResults(keyUseAesSwDec, "keyUseAesSwDec");
                return keyUseAesSwDec;

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
                    signature.initSign(keyPairSwECDSA.getPrivate());

                    signature.update(data);
                    signatureCreatedECDSA = signature.sign();
                    stop = System.nanoTime();

                    keyUseEcSwSig[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
                }
                BenchmarkingResults.storeResults(keyUseEcSwSig, "keyUseEcSwSig");
                return keyUseEcSwSig;

            } else if (useKeyPos == 3) {
                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instanceSign);
                    signature.initVerify(keyPairSwECDSA.getPublic());

                    signature.update(data);
                    signature.verify(signatureCreatedECDSA);
                    stop = System.nanoTime();

                    keyUseEcSwVer[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
                }
                BenchmarkingResults.storeResults(keyUseEcSwVer, "keyUseEcSwVer");
                return keyUseEcSwVer;
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
                    mac.init(keySwHMAC);
                    macCreated = mac.doFinal(data);
                    stop = System.nanoTime();

                    keyUseHmacSwSig[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
                }
                BenchmarkingResults.storeResults(keyUseHmacSwSig, "keyUseHmacSwSig");
                return keyUseHmacSwSig;

            } else if (useKeyPos == 3) {

                for (int i = 0; i < Parameters.RUNS; i++) {
                    start = System.nanoTime();
                    Mac mac = Mac.getInstance("HmacSHA256");

                    mac.init(keySwHMAC);
                    mac.doFinal(macCreated);
                    stop = System.nanoTime();

                    keyUseHmacSwVer[i] = (stop - start)/Parameters.MEASURETIME;

                    Thread.sleep(Parameters.SLEEPTIME);
                }
                BenchmarkingResults.storeResults(keyUseHmacSwVer, "keyUseHmacSwVer");
                return keyUseHmacSwVer;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
