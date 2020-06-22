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

class CryptographyTee {

    private static KeyPair keyPairTeeRSA;
    private static KeyPair keyPairTeeECDSA;
    private static SecretKey keyTeeHMAC;
    private static SecretKey keyTeeAES;
    private static String keyProperties = null;

    private static byte[] signatureCreatedRSA = new byte[0];
    private static byte[] signatureCreatedECDSA = new byte[0];

    private static byte[] cipherCreatedRSA = new byte[0];

    private static byte[] cipherCreatedAES = new byte[0];

    private static byte[] macCreated = new byte[0];

    // keygen arrays
    public static long[] keyGenRsaTeeEnc = new long[10];
    public static long[] keyGenRsaTeeSig = new long[10];

    public static long[] keyGenAesTeeEnc = new long[10];

    public static long[] keyGenEcTeeEnc = new long[10];

    public static long[] keyGenHmacTeeEnc = new long[10];

    //keyuse arrays
    public static long[] keyUseRsaTeeEnc = new long[10];
    public static long[] keyUseRsaTeeDec = new long[10];
    public static long[] keyUseRsaTeeSig = new long[10];
    public static long[] keyUseRsaTeeVer = new long[10];

    public static long[] keyUseAesTeeEnc = new long[10];
    public static long[] keyUseAesTeeDec = new long[10];

    public static long[] keyUseEcTeeEnc = new long[10];
    public static long[] keyUseEcTeeDec = new long[10];

    public static long[] keyUseHmacTeeEnc = new long[10];
    public static long[] keyUseHmacTeeDec = new long[10];


    static long[] createKeysRSA(int usePos) throws Exception {

        int keyUsage = 0;
        String keyAlias = "keyTee" + "RSA" + usePos;
        keyProperties = KeyProperties.KEY_ALGORITHM_RSA;

        if (usePos == 0) {
            keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        } else if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long timeGenKey;
        for (int i = 0; i < 10; i++) {

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
            timeGenKey = (stopGen - startGen);

            PrivateKey key = keyPairTeeRSA.getPrivate();
            KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo;
            try {
                keyInfo = factory.getKeySpec(key, KeyInfo.class);
                System.out.println("Tee" + keyInfo.isInsideSecureHardware());
            } catch (InvalidKeySpecException e) {
                // Not an Android KeyStore key.
            }

            if (usePos == 0) {
                keyGenRsaTeeEnc[i] = timeGenKey;
            } else if (usePos == 1) {
                keyGenRsaTeeSig[i] = timeGenKey;
            }

        }
        if (usePos == 0) {
            return keyGenRsaTeeEnc;
        } else if (usePos == 1) {
            return keyGenRsaTeeSig;
        }
        return null;
    }


    static long[] createKeysAES(int usePos) throws Exception {

        String keyAlias = "keyTee" + "AES" + usePos;
        int keyUsage = 0;

        if (usePos == 0) {
            keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);

        }

        long timeGenKey;

        for (int i = 0; i < 10; i++) {
            long startGen = System.nanoTime();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(keyAlias, keyUsage)
                            .setKeySize(256)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                            .setIsStrongBoxBacked(false)
                            .build());
            keyTeeAES = keyGenerator.generateKey();

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen);

            keyGenAesTeeEnc[i] = timeGenKey;
        }

        return keyGenAesTeeEnc;
    }


    static long[] createKeysECDSA(int usePos) throws Exception {

        int keyUsage = 0;
        String keyAlias = "keyTee" + "ECDSA" + usePos;

        keyProperties = KeyProperties.KEY_ALGORITHM_EC;

        if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long timeGenKey;

        for (int i = 0; i < 10; i++) {
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
            timeGenKey = (stopGen - startGen);

            keyGenEcTeeEnc[i] = timeGenKey;

        }

        return keyGenEcTeeEnc;

    }


    static long[] createKeysHMAC(int usePos) throws Exception {

        String keyAlias = "keyTee" + "HMAC" + usePos;
        int keyUsage = 0;

        if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long timeGenKey;
        for (int i = 0; i < 10; i++) {

            long startGen = System.nanoTime();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore");
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(keyAlias, keyUsage)
                            .setIsStrongBoxBacked(false)
                            .build());
            keyTeeHMAC = keyGenerator.generateKey();
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keyTeeHMAC);

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen);

            keyGenHmacTeeEnc[i] = timeGenKey;
        }

        return keyGenHmacTeeEnc;
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
                    cipher.init(Cipher.ENCRYPT_MODE, keyPairTeeRSA.getPublic());

                    cipherCreatedRSA = cipher.doFinal(data);
                    stop = System.nanoTime();

                    keyUseRsaTeeEnc[i] = (stop - start);
                    System.out.println(keyUseRsaTeeEnc[i]);

                }
                return keyUseRsaTeeEnc;
            } else if (useKeyPos == 1) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher2.init(Cipher.DECRYPT_MODE, keyPairTeeRSA.getPrivate());

                    cipher2.doFinal(cipherCreatedRSA);
                    stop = System.nanoTime();
                    keyUseRsaTeeDec[i] = (stop - start);

                }
                return keyUseRsaTeeDec;
            } else if (useKeyPos == 2) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instance);
                    signature.initSign(keyPairTeeRSA.getPrivate());

                    signature.update(data);
                    signatureCreatedRSA = signature.sign();
                    keyUseRsaTeeSig[i] = (stop - start);

                }
                return keyUseRsaTeeSig;

            } else if (useKeyPos == 3) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instance);
                    signature.initVerify(keyPairTeeRSA.getPublic());

                    signature.update(data);
                    signature.verify(signatureCreatedRSA);
                    stop = System.nanoTime();
                    keyUseRsaTeeVer[i] = (stop - start);

                }
                return keyUseRsaTeeVer;
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
                    cipher.init(Cipher.ENCRYPT_MODE, keyTeeAES);

                    cipherCreatedAES = cipher.doFinal(data);
                    stop = System.nanoTime();

                    keyUseAesTeeEnc[i] = (stop - start);
                }
                return keyUseAesTeeEnc;

            } else if (useKeyPos == 4) {

                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    cipher.init(Cipher.DECRYPT_MODE, keyTeeAES);

                    cipher.doFinal(cipherCreatedAES);
                    stop = System.nanoTime();

                    keyUseAesTeeDec[i] = (stop - start);
                }
                return keyUseAesTeeDec;

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
                    signature.initSign(keyPairTeeECDSA.getPrivate());

                    signature.update(data);
                    signatureCreatedECDSA = signature.sign();
                    stop = System.nanoTime();

                    keyUseEcTeeEnc[i] = (stop - start);
                }

                return keyUseEcTeeEnc;

            } else if (useKeyPos == 3) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instanceSign);
                    signature.initVerify(keyPairTeeECDSA.getPublic());

                    signature.update(data);
                    signature.verify(signatureCreatedECDSA);
                    stop = System.nanoTime();

                    keyUseEcTeeDec[i] = (stop - start);
                }
                return keyUseEcTeeDec;
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
                    mac.init(keyTeeHMAC);
                    macCreated = mac.doFinal(data);
                    stop = System.nanoTime();

                    keyUseHmacTeeEnc[i] = (stop - start);
                }
                return keyUseHmacTeeEnc;

            } else if (useKeyPos == 3) {

                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Mac mac = Mac.getInstance("HmacSHA256");

                    mac.init(keyTeeHMAC);
                    mac.doFinal(macCreated);
                    stop = System.nanoTime();

                    keyUseHmacTeeDec[i] = (stop - start);
                }
                return keyUseHmacTeeDec;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
