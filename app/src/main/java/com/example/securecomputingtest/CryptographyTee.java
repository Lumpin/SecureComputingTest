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

class CryptographyTee {

    private static KeyPair keyPairTeeRSA;
    private static KeyPair keyPairTeeECDSA;
    private static SecretKey keyTeeHMAC;
    private static SecretKey keyTeeAES;
    private static String s = "";
    private static String keyProperties = null;

    private static byte[] signatureCreatedRSA = new byte[0];
    private static byte[] signatureCreatedECDSA = new byte[0];

    private static byte[] cipherCreatedRSA = new byte[0];
    private static byte[] cipherDecryptedRSA = new byte[0];

    private static byte[] cipherCreatedEC = new byte[0];
    private static byte[] cipherDecryptedEC = new byte[0];

    private static byte[] cipherCreatedAES = new byte[0];
    private static byte[] cipherDecryptedAES = new byte[0];


    private static byte[] macCreated = new byte[0];
    private static byte[] macDecrypted = new byte[0];

    // keygen arrays
    public static long keyGenRsaTeeEnc[] = new long[10];
    public static long keyGenRsaTeeSig[] = new long[10];

    public static long keyGenAesTeeEnc[] = new long[10];

    public static long keyGenEcTeeEnc[] = new long[10];

    public static long keyGenHmacTeeEnc[] = new long[10];

    //keyuse arrays
    public static long keyUseRsaTeeEnc[] = new long[10];
    public static long keyUseRsaTeeDec[] = new long[10];
    public static long keyUseRsaTeeSig[] = new long[10];
    public static long keyUseRsaTeeVer[] = new long[10];

    public static long keyUseAesTeeEnc[] = new long[10];
    public static long keyUseAesTeeDec[] = new long[10];

    public static long keyUseEcTeeEnc[] = new long[10];
    public static long keyUseEcTeeDec[] = new long[10];

    public static long keyUseHmacTeeEnc[] = new long[10];
    public static long keyUseHmacTeeDec[] = new long[10];


    static String createKeysRSA(int usePos) throws Exception {

        int keyUsage = 0;
        String keyAlias = "keyTee" + "RSA" + usePos;
        keyProperties = KeyProperties.KEY_ALGORITHM_RSA;

        if (usePos == 0) {
            keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);
        } else if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }
        long timeGenKey = 0;
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

            if (usePos == 0) {
                keyGenRsaTeeEnc[i] = timeGenKey;
            } else if (usePos == 1) {
                keyGenRsaTeeSig[i] = timeGenKey;
            }

        }

        s = "Generation time in TEE: " + timeGenKey + " ns of Key: " + keyAlias;
        return s;

    }


    static String createKeysAES(int usePos) throws Exception {

        String keyAlias = "keyTee" + "AES" + usePos;
        int keyUsage = 0;

        if (usePos == 0) {
            keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);

        } else if (usePos == 1) {
            s = "not supported";
        }

        long timeGenKey = 0;

        for (int i = 0; i < 10; i++) {
            long startGen = System.nanoTime();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(keyAlias, keyUsage)
                            .setKeySize(256)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                            .build());
            keyTeeAES = keyGenerator.generateKey();

            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen);

            keyGenAesTeeEnc[i] = timeGenKey;
        }
        s = "Generation time in TEE: " + timeGenKey + " ns of Key: " + keyAlias;

        return s;
    }


    static String createKeysECDSA(int usePos) throws Exception {

        int keyUsage = 0;
        String keyAlias = "keyTee" + "ECDSA" + usePos;

        keyProperties = KeyProperties.KEY_ALGORITHM_EC;

        if (usePos == 0) {
            s = "not supported";
        } else if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long timeGenKey = 0;

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
        s = "Generation time in TEE: " + timeGenKey + " ns of Key: " + keyAlias;

        return s;
    }


    static String createKeysHMAC(int usePos) throws Exception {

        String keyAlias = "keyTee" + "HMAC" + usePos;
        int keyUsage = 0;

        if (usePos == 0) {
            s = "not supported";
        } else if (usePos == 1) {
            keyUsage = (KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY);
        }

        long timeGenKey = 0;
        for (int i = 0; i < 10; i++) {

            long startGen = System.nanoTime();
            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore");
            keyGenerator.init(
                    new KeyGenParameterSpec.Builder(keyAlias, keyUsage).build());
            keyTeeHMAC = keyGenerator.generateKey();
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(keyTeeHMAC);
            long stopGen = System.nanoTime();
            timeGenKey = (stopGen - startGen);

            keyGenHmacTeeEnc[i] = timeGenKey;
        }
        s = "Generation time in TEE: " + timeGenKey + " ns of Key: " + keyAlias;

        return s;
    }


    static String useKeysRSA(int useKeyPos) {

        try {

            int useKey = 0;
            byte data[] = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};
            boolean valid = false;
            String instance = "";

            if (useKeyPos == 0 || useKeyPos == 1) {
                useKey = 0;
            } else if (useKeyPos == 2 || useKeyPos == 3) {
                useKey = 1;
            }

            String keyAlias = "keyTee" + "RSA" + useKey;

            instance = "SHA256withRSA";


            long start = System.nanoTime();
            long stop = System.nanoTime();

            if (useKeyPos == 0) {
                for (int i = 0; i < 10; i++) {

                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher.init(cipher.ENCRYPT_MODE, keyPairTeeRSA.getPublic());

                    cipherCreatedRSA = cipher.doFinal(data);
                    stop = System.nanoTime();

                    keyUseRsaTeeEnc[i] = (stop - start);
                }

            } else if (useKeyPos == 1) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher2.init(cipher2.DECRYPT_MODE, keyPairTeeRSA.getPrivate());

                    cipherDecryptedRSA = cipher2.doFinal(cipherCreatedRSA);
                    stop = System.nanoTime();
                    keyUseRsaTeeDec[i] = (stop - start);
                }
            } else if (useKeyPos == 2) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instance);
                    signature.initSign(keyPairTeeRSA.getPrivate());

                    signature.update(data);
                    signatureCreatedRSA = signature.sign();
                    keyUseRsaTeeSig[i] = (stop - start);
                }

            } else if (useKeyPos == 3) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instance);
                    signature.initVerify(keyPairTeeRSA.getPublic());

                    signature.update(data);
                    valid = signature.verify(signatureCreatedRSA);
                    stop = System.nanoTime();
                    keyUseRsaTeeSig[i] = (stop - start);
                }
            }

            long timeSig = (stop - start);

            if (useKeyPos == 0) {
                s = keyAlias
                        + "Time for enc entry '123': " + timeSig + " ns" +
                        " \n" + "\n"
                        + "Created enc";

            } else if (useKeyPos == 1) {
                s = keyAlias
                        + "Time for dec entry '123': " + timeSig + " ns" +
                        " \n"
                        + "data is decrypted: ";
            } else if (useKeyPos == 2) {
                s = keyAlias
                        + "Time for signing entry '123': " + timeSig + " ns" +
                        " \n" + "\n"
                        + "Created signature";
            } else if (useKeyPos == 3) {
                s = keyAlias
                        + "Time for verifying entry '123': " + timeSig + " ns" +
                        " \n"
                        + "data is valid: " + valid;
            }
            return s;
        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }
    }

    static String useKeysAES(int useKeyPos) {
        try {

            int useKey = 0;

            byte data[] = {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1,
                    (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1};
            boolean valid = false;

            if (useKeyPos == 0 || useKeyPos == 1) {
                useKey = 0;
            } else if (useKeyPos == 2 || useKeyPos == 3) {
                useKey = 1;
            }

            String keyAlias = "keyTee" + "AES" + useKey;

            long start = System.nanoTime();
            long stop = System.nanoTime();

            if (useKeyPos == 3) {

                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    cipher.init(cipher.ENCRYPT_MODE, keyTeeAES);

                    cipherCreatedAES = cipher.doFinal(data);
                    stop = System.nanoTime();

                    keyUseAesTeeEnc[i] = (stop - start);
                }
            } else if (useKeyPos == 4) {


                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                    cipher.init(cipher.DECRYPT_MODE, keyTeeAES);

                    cipherDecryptedAES = cipher.doFinal(cipherCreatedAES);
                    stop = System.nanoTime();

                    keyUseAesTeeDec[i] = (stop - start);
                }

            }

            long timeSig = (stop - start);

            if (useKeyPos == 0) {
                s = keyAlias
                        + "Time for enc entry '123': " + timeSig + " ns" +
                        " \n" + "\n"
                        + "Created enc";

            } else if (useKeyPos == 1) {
                s = keyAlias
                        + "Time for dec entry '123': " + timeSig + " ns" +
                        " \n"
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

    static String useKeysECDSA(int useKeyPos) {
        try {

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

            String keyAlias = "keyTee" + "ECDSA" + useKey;

            instanceSign = "SHA256withECDSA";

            long start = System.nanoTime();
            long stop = System.nanoTime();

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

            } else if (useKeyPos == 3) {
                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Signature signature = Signature.getInstance(instanceSign);
                    signature.initVerify(keyPairTeeECDSA.getPublic());

                    signature.update(data);
                    valid = signature.verify(signatureCreatedECDSA);
                    stop = System.nanoTime();

                    keyUseEcTeeDec[i] = (stop - start);
                }
            }
            long timeSig = (stop - start);

            if (useKeyPos == 2) {
                s = keyAlias
                        + "Time for signing entry '123': " + timeSig + " ns" +
                        " \n" + "\n"
                        + "Created signature";
            } else if (useKeyPos == 3) {
                s = keyAlias
                        + "Time for verifying entry '123': " + timeSig + " ns" +
                        " \n"
                        + "data is valid: " + valid;
            }
            return s;
        } catch (Exception e) {

            e.printStackTrace();
            return "Error";
        }

    }

    static String userKeysHMAC(int useKeyPos) {
        try {

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

            if (useKeyPos == 2) {

                for (int i = 0; i < 10; i++) {

                    start = System.nanoTime();
                    Mac mac = Mac.getInstance("HmacSHA256");
                    mac.init(keyTeeHMAC);
                    macCreated = mac.doFinal(data);
                    stop = System.nanoTime();

                    keyUseHmacTeeEnc[i] = (stop - start);
                }

            } else if (useKeyPos == 3) {

                for (int i = 0; i < 10; i++) {
                    start = System.nanoTime();
                    Mac mac = Mac.getInstance("HmacSHA256");

                    mac.init(keyTeeHMAC);
                    macDecrypted = mac.doFinal(macCreated);
                    stop = System.nanoTime();

                    keyUseHmacTeeDec[i] = (stop - start);
                }
            }

            long timeSig = (stop - start);

            if (useKeyPos == 2) {
                s = keyAlias
                        + "Time for signing entry '123': " + timeSig + " ns" +
                        " \n"
                        + "Created mac";
            } else if (useKeyPos == 3) {
                s = keyAlias
                        + "Time for verifying entry '123': " + timeSig + " ns" +
                        " \n"
                        + "data is valid: ";
            }
            return s;
        } catch (Exception e) {

            e.printStackTrace();
            return "Error";
        }

    }
}
