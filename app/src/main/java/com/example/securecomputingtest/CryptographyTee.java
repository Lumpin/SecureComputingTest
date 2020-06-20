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
    private static byte[] macDecrypted= new byte[0];

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

    static String createKeysAES(int usePos) throws Exception {

        String keyAlias = "keyTee" + "AES" + usePos;
        int keyUsage = 0;

        if (usePos == 0) {
            keyUsage = (KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT);

        }

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
        long timeGenKey = (stopGen - startGen) / 1000000;

        return s;
    }


    /**
     * @param usePos
     * @return
     * @throws Exception
     */
    static String createKeysECDSA(int usePos) throws Exception {

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


    /**
     * @param usePos
     * @return
     * @throws Exception
     */
    static String createKeysHMAC(int usePos) throws Exception {

        String keyAlias = "keyTee" + "HMAC" + usePos;
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
                new KeyGenParameterSpec.Builder(keyAlias, keyUsage).build());
        keyTeeHMAC = keyGenerator.generateKey();
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keyTeeHMAC);
        long stopGen = System.nanoTime();
        long timeGenKey = (stopGen - startGen) / 1000000;

        s = "Generation time in TEE: " + timeGenKey + " ms of Key: " + keyAlias;

        return s;
    }

    /**
     * @param useKeyPos
     * @return
     * @throws Exception
     */
    static String useKeysRSA(int useKeyPos) {

        try {
            /*********************************************************************************************/

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

            String keyAlias = "keyTee" + "RSA" + useKey;

            instance = "SHA256withRSA";


            /**************** obtaining key *********************************************************************/
            long startGetKey = System.nanoTime();

            long stopGetKey = System.nanoTime();


            /********** using key **********************************************/
            long start = System.nanoTime();

            if (useKeyPos == 0) {

                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(cipher.ENCRYPT_MODE, keyPairTeeRSA.getPublic());

                cipherCreatedRSA = cipher.doFinal(data);


            } else if (useKeyPos == 1) {
                Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher2.init(cipher2.DECRYPT_MODE,keyPairTeeRSA.getPrivate());

                cipherDecryptedRSA = cipher2.doFinal(cipherCreatedRSA);

            } else if (useKeyPos == 2) {

                Signature signature = Signature.getInstance(instance);
                signature.initSign(keyPairTeeRSA.getPrivate());

                signature.update(data);
                signatureCreatedRSA = signature.sign();

            } else if (useKeyPos == 3) {

                Signature signature = Signature.getInstance(instance);
                signature.initVerify(keyPairTeeRSA.getPublic());

                signature.update(data);
                valid = signature.verify(signatureCreatedRSA);

            }

            long stop = System.nanoTime();

            /************* String generation ***********************************************************************/
            //for ms divide by 1000000

            long timeElapsedGetKey = (stopGetKey - startGetKey) / 1000000;
            long timeSig = (stop - start) / 1000000;


            if (useKeyPos == 0) {
                s = keyAlias+
                        "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                        + "Time for enc entry '123': " + timeSig + " ms \n" + "\n"
                        + "Created enc";

            } else if (useKeyPos == 1) {
                     s=    keyAlias+ "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                        + "Time for dec entry '123': " + timeSig + " ms \n"
                        + "data is decrypted: ";
            } else if (useKeyPos == 2) {
                s = keyAlias+
                        "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                        + "Time for signing entry '123': " + timeSig + " ms \n" + "\n"
                        + "Created signature";
            } else if (useKeyPos == 3) {
                s = keyAlias+
                        "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                        + "Time for verifying entry '123': " + timeSig + " ms \n"
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

            System.out.println(data.toString());

            if (useKeyPos == 0 || useKeyPos == 1) {
                useKey = 0;
            } else if (useKeyPos == 2 || useKeyPos == 3) {
                useKey = 1;
            }

            String keyAlias = "keyTee" + "AES" + useKey;


            /**************** obtaining key *********************************************************************/
            long startGetKey = System.nanoTime();



            long stopGetKey = System.nanoTime();


            /********** using key **********************************************/
            long start = System.nanoTime();

            if (useKeyPos == 3) {

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                cipher.init(cipher.ENCRYPT_MODE,  keyTeeAES);

                cipherCreatedAES = cipher.doFinal(data);


            } else if (useKeyPos == 4) {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
                cipher.init(cipher.DECRYPT_MODE, keyTeeAES);

                cipherDecryptedAES = cipher.doFinal(cipherCreatedAES);

            }
                long stop = System.nanoTime();

                /************* String generation ***********************************************************************/
                //for ms divide by 1000000

                long timeElapsedGetKey = (stopGetKey - startGetKey) / 1000000;
                long timeSig = (stop - start) / 1000000;


                if (useKeyPos == 0) {
                    s =       keyAlias+
                             "Key: " + keyTeeAES.toString() + "\n"
                            + "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                            + "Time for enc entry '123': " + timeSig + " ms \n" + "\n"
                            + "Created enc";

                } else if (useKeyPos == 1) {
                    s = keyAlias+
                            "Key: " + keyTeeAES.toString() + "\n"
                            + "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                            + "Time for dec entry '123': " + timeSig + " ms \n"
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
     * @param useKeyPos
     * @return
     * @throws Exception
     */
    static String useKeysECDSA(int useKeyPos) {
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

            String keyAlias = "keyTee" + "ECDSA" + useKey;

            instanceSign = "SHA256withECDSA";


            /**************** obtaining key *********************************************************************/
            long startGetKey = System.nanoTime();


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

            long timeElapsedGetKey = (stopGetKey - startGetKey) / 1000000;
            long timeSig = (stop - start) / 1000000;


            if (useKeyPos == 0) {

            } else if (useKeyPos == 1) {

            } else if (useKeyPos == 2) {
                s = keyAlias+
                        "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                        + "Time for signing entry '123': " + timeSig + " ms \n" + "\n"
                        + "Created signature";
            } else if (useKeyPos == 3) {
                s = keyAlias+
                        "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                        + "Time for verifying entry '123': " + timeSig + " ms \n"
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




            /**************** obtaining key *********************************************************************/
            long startGetKey = System.nanoTime();


            long stopGetKey = System.nanoTime();

            /********** using key **********************************************/
            long start = System.nanoTime();

            if (useKeyPos == 0) {


            } else if (useKeyPos == 1) {

            } else if (useKeyPos == 2) {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(keyTeeHMAC);


                macCreated = mac.doFinal(data);


            } else if (useKeyPos == 3) {

                Mac mac = Mac.getInstance("HmacSHA256");

                mac.init(keyTeeHMAC);
                macDecrypted = mac.doFinal(macCreated);
            }

            long stop = System.nanoTime();

            /************* String generation ***********************************************************************/
            //for ms divide by 1000000

            long timeElapsedGetKey = (stopGetKey - startGetKey) / 1000000;
            long timeSig = (stop - start) / 1000000;


            if (useKeyPos == 0) {

            } else if (useKeyPos == 1) {

            } else if (useKeyPos == 2) {
                s = keyAlias+
                        "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                        + "Time for signing entry '123': " + timeSig + " ms \n" + "\n"
                        + "Created mac";
            } else if (useKeyPos == 3) {
                s = keyAlias+
                        "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                        + "Time for verifying entry '123': " + timeSig + " ms \n"
                        + "data is valid: " ;
            }
            return s;
        } catch (Exception e) {

            e.printStackTrace();
            return "Error";
        }

    }
}
