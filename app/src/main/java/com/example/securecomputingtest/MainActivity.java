package com.example.securecomputingtest;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class MainActivity extends AppCompatActivity {

    private TextView time;
    private TextView textApplication;

    private Spinner spinnerM;
    private Spinner spinnerAlgo;
    private Spinner spinnerUse;
    private Spinner spinnerHw;

    KeyPair keyPairSE;
    KeyPair keyPairTEE;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        spinnerM = (Spinner) findViewById((R.id.spinnerM));
        spinnerAlgo = (Spinner) findViewById((R.id.spinnerAlgo));
        spinnerUse = (Spinner) findViewById((R.id.spinnerUse));
        spinnerHw = (Spinner) findViewById((R.id.spinnerHw));


        ArrayAdapter<CharSequence> adapterM = ArrayAdapter.createFromResource(this,
                R.array.spinner_m, android.R.layout.simple_spinner_item);
        ArrayAdapter<CharSequence> adapterAlgo = ArrayAdapter.createFromResource(this,
                R.array.spinner_algo, android.R.layout.simple_spinner_item);
        ArrayAdapter<CharSequence> adapterUse = ArrayAdapter.createFromResource(this,
                R.array.spinner_use, android.R.layout.simple_spinner_item);
        ArrayAdapter<CharSequence> adapterHw = ArrayAdapter.createFromResource(this,
                R.array.spinner_hw, android.R.layout.simple_spinner_item);

        adapterM.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        adapterAlgo.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        adapterUse.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        adapterHw.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);

        spinnerM.setAdapter(adapterM);
        spinnerAlgo.setAdapter(adapterAlgo);
        spinnerUse.setAdapter(adapterUse);
        spinnerHw.setAdapter(adapterHw);

        time = (TextView) findViewById(R.id.time);
        textApplication = (TextView) findViewById(R.id.textApplication);
        Button buttonStart = (Button) findViewById(R.id.buttonStart);
        buttonStart.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                String s = "";
                try {
                    if (spinnerHw.getSelectedItemPosition() == 0) {
                        s = saveInSw(spinnerAlgo.getSelectedItemPosition(), spinnerUse.getSelectedItemPosition());
                        time.setText(s);
                    } else if (spinnerHw.getSelectedItemPosition() == 1) {
                        s = saveInTee(spinnerAlgo.getSelectedItemPosition(), spinnerUse.getSelectedItemPosition());
                        time.setText(s);

                    } else if (spinnerHw.getSelectedItemPosition() == 2) {
                        s = saveInSe(spinnerAlgo.getSelectedItemPosition(), spinnerUse.getSelectedItemPosition());
                        time.setText(s);
                    }
                } catch (Exception e) {
                    time.setText("Generation Error");
                }

            }
        });

        Button buttonSign = (Button) findViewById(R.id.buttonSign);

        buttonSign.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                String s = "";
                try {
                    if (spinnerHw.getSelectedItemPosition() == 0) {
                        s = useSw(spinnerM.getSelectedItemPosition(), spinnerAlgo.getSelectedItemPosition(), spinnerUse.getSelectedItemPosition());
                        textApplication.setText(s);
                    } else if (spinnerHw.getSelectedItemPosition() == 1) {
                        s = useTee(spinnerM.getSelectedItemPosition(), spinnerAlgo.getSelectedItemPosition(), spinnerUse.getSelectedItemPosition());
                        textApplication.setText(s);

                    } else if (spinnerHw.getSelectedItemPosition() == 2) {
                        s = useSe(spinnerM.getSelectedItemPosition(), spinnerAlgo.getSelectedItemPosition(), spinnerUse.getSelectedItemPosition());
                        textApplication.setText(s);
                    }
                } catch (Exception e) {
                    textApplication.setText("Application Error");
                }


            }
        });
    }

    /**
     * @param algoPos
     * @param usePos
     * @return
     * @throws NoSuchAlgorithmException
     */
    public String saveInSw(int algoPos, int usePos) throws NoSuchAlgorithmException {

        String keyProperties = null;
        String keyAlias = "keySE" + algoPos + usePos;
        int keyUsage;

        KeyGenerator keyGenerator;
        SecretKey secretKey;
        keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        secretKey = keyGenerator.generateKey();

        if (algoPos == 0) {

        } else if (algoPos == 1) {

        } else if (algoPos == 2) {

        } else if (algoPos == 3) {

        } else if (algoPos == 4) {

        }

        if (usePos == 0) {
            keyUsage = KeyProperties.PURPOSE_ENCRYPT;
        } else if (usePos == 1) {
            keyUsage = KeyProperties.PURPOSE_DECRYPT;
        } else if (usePos == 2) {
            keyUsage = KeyProperties.PURPOSE_SIGN;
        } else if (usePos == 3) {
            keyUsage = KeyProperties.PURPOSE_VERIFY;
        }
        return "Software";
    }


    /**
     * @param algoPos
     * @param usePos
     * @return
     */
    public String saveInSe(int algoPos, int usePos) {

        String keyProperties = null;
        int keyUsage = 0;
        String keyAlias = "keySE" + algoPos + usePos;

        if (algoPos == 0) {
            keyProperties = KeyProperties.KEY_ALGORITHM_RSA;
        } else if (algoPos == 1) {
            keyProperties = KeyProperties.KEY_ALGORITHM_AES;
        } else if (algoPos == 2) {
            keyProperties = KeyProperties.KEY_ALGORITHM_EC;
        } else if (algoPos == 3) {
            keyProperties = KeyProperties.KEY_ALGORITHM_HMAC_SHA256;
        } else if (algoPos == 4) {
            keyProperties = KeyProperties.KEY_ALGORITHM_HMAC_SHA256;
        }

        if (usePos == 0) {
            keyUsage = KeyProperties.PURPOSE_ENCRYPT;
        } else if (usePos == 1) {
            keyUsage = KeyProperties.PURPOSE_DECRYPT;
        } else if (usePos == 2) {
            keyUsage = KeyProperties.PURPOSE_SIGN;
        } else if (usePos == 3) {
            keyUsage = KeyProperties.PURPOSE_VERIFY;
        }
        try {
            long startGen = System.nanoTime();

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    keyProperties, "AndroidKeyStore");

            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            keyAlias,
                            keyUsage)
                            .setIsStrongBoxBacked(true)
                            .build());

            keyPairSE = keyPairGenerator.generateKeyPair();

            long stopGen = System.nanoTime();

            long timeGenKey = (stopGen - startGen) / 1000000;

            String s = "Generation time in SE: " + timeGenKey + " ms of Key: " + keyAlias;
            return s;

        } catch (Exception e) {

            e.printStackTrace();
            return "StrongBox unavailable";
        }
    }

    /**
     * @param algoPos
     * @param usePos
     * @return
     * @throws Exception
     */
    public String saveInTee(int algoPos, int usePos) throws Exception {

        String keyProperties = null;
        int keyUsage = 0;
        String keyAlias = "keySE" + algoPos + usePos;

        if (algoPos == 0) {
            keyProperties = KeyProperties.KEY_ALGORITHM_RSA;
        } else if (algoPos == 1) {
            keyProperties = KeyProperties.KEY_ALGORITHM_AES;
        } else if (algoPos == 2) {
            keyProperties = KeyProperties.KEY_ALGORITHM_EC;
        } else if (algoPos == 3) {
            keyProperties = KeyProperties.KEY_ALGORITHM_HMAC_SHA256;
        } else if (algoPos == 4) {
            keyProperties = KeyProperties.KEY_ALGORITHM_HMAC_SHA256;
        }

        if (usePos == 0) {
            keyUsage = KeyProperties.PURPOSE_ENCRYPT;
        } else if (usePos == 1) {
            keyUsage = KeyProperties.PURPOSE_DECRYPT;
        } else if (usePos == 2) {
            keyUsage = KeyProperties.PURPOSE_SIGN;
        } else if (usePos == 3) {
            keyUsage = KeyProperties.PURPOSE_VERIFY;
        }

        long startGen = System.nanoTime();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                keyProperties, "AndroidKeyStore");

        keyPairGenerator.initialize(
                new KeyGenParameterSpec.Builder(
                        keyAlias,
                        keyUsage)
                        .setIsStrongBoxBacked(false)
                        .build());

        keyPairTEE = keyPairGenerator.generateKeyPair();

        long stopGen = System.nanoTime();

        long timeGenKey = (stopGen - startGen) / 1000000;

        String s = "Generation time in TEE: " + timeGenKey + " ms of Key: " + keyAlias;
        return s;
    }


    public String useSw(int messagePos, int algoPos, int usePos) {

        String s = "";

        if (messagePos == 0) {

        } else if (messagePos == 1) {

        } else if (messagePos == 2) {

        }

        if (algoPos == 0) {

        } else if (algoPos == 1) {

        } else if (algoPos == 2) {

        } else if (algoPos == 3) {

        } else if (algoPos == 4) {

        }

        if (usePos == 0) {

        } else if (usePos == 1) {

        } else if (usePos == 2) {

        } else if (usePos == 3) {

        }

        return s;
    }


    public String useTee(int messagePos, int algoPos, int usePos) throws Exception{

        String keyProperties = null;
        int keyUsage = 0;
        String keyAlias = "keySE" + algoPos + usePos;

        String s = "";

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

        if (messagePos == 0) {

        } else if (messagePos == 1) {

        } else if (messagePos == 2) {

        }


        if (algoPos == 0) {
            keyProperties = KeyProperties.KEY_ALGORITHM_RSA;
        } else if (algoPos == 1) {
            keyProperties = KeyProperties.KEY_ALGORITHM_AES;
        } else if (algoPos == 2) {
            keyProperties = KeyProperties.KEY_ALGORITHM_EC;
        } else if (algoPos == 3) {
            keyProperties = KeyProperties.KEY_ALGORITHM_HMAC_SHA256;
        } else if (algoPos == 4) {
            keyProperties = KeyProperties.KEY_ALGORITHM_HMAC_SHA256;
        }

        if (usePos == 0) {
            keyUsage = KeyProperties.PURPOSE_ENCRYPT;
        } else if (usePos == 1) {
            keyUsage = KeyProperties.PURPOSE_DECRYPT;
        } else if (usePos == 2) {
            keyUsage = KeyProperties.PURPOSE_SIGN;
        } else if (usePos == 3) {
            keyUsage = KeyProperties.PURPOSE_VERIFY;
        }

        long startSig = System.nanoTime();

        Signature signature = Signature.getInstance("SHA256withRSA/PSS");
        signature.initSign(keyPairTEE.getPrivate());

        signature.initSign(privateKey);
        signature.update((byte) 123);

        byte[] signatureCreated = signature.sign();
        long stopSig = System.nanoTime();

        //for ms divide by 1000000

        String secureHW = "";

        if (keyInfo.isInsideSecureHardware()) {
            secureHW = "Key is inside secure hardware";
        } else {
            secureHW = "Key is NOT inside secure hardware";
        }

        long timeElapsedGetKey = (stopGetKey - startGetKey) / 1000000;
        long timeSig = (stopSig - startSig) / 1000000;

        s = secureHW + "\n" + "\n"
                + "Private Key: " + privateKey.toString() + "\n"
                + "Public Key: " + publicKey.toString() + "\n" + "\n"
                + "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                + "Time for signing entry '123': " + timeSig + " ms \n" + "\n"
                + "Created signature: " + signatureCreated;
        return s;
    }


    public String useSe(int messagePos, int algoPos, int usePos) {
        String s = "";

        if (messagePos == 0) {

        } else if (messagePos == 1) {

        } else if (messagePos == 2) {

        }


        if (algoPos == 0) {

        } else if (algoPos == 1) {

        } else if (algoPos == 2) {

        } else if (algoPos == 3) {

        } else if (algoPos == 4) {

        }


        if (usePos == 0) {

        } else if (usePos == 1) {

        } else if (usePos == 2) {

        } else if (usePos == 3) {

        }

        return s;
    }


    public void signInSE() throws Exception {

        long startGetKey = System.nanoTime();
        // The key pair can also be obtained from the Android Keystore any time as follows:
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("keySE", null);
        KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
        KeyInfo keyInfo = null;
        try {
            keyInfo = factory.getKeySpec(privateKey, KeyInfo.class);
        } catch (InvalidKeySpecException e) {
            // Not an Android KeyStore key.
        }
        PublicKey publicKey = keyStore.getCertificate("keySE").getPublicKey();

        long startSig = System.nanoTime();

        Signature signature = Signature.getInstance("SHA256withRSA/PSS");
        signature.initSign(keyPairSE.getPrivate());

        signature.initSign(privateKey);
        signature.update((byte) 123);

        byte[] signatureCreated = signature.sign();
        long stopSig = System.nanoTime();

        long stopGetKey = System.nanoTime();
        //for ms divide by 1000000

        String secureHW = "";
        if (keyInfo.isInsideSecureHardware()) {
            secureHW = "Key is inside secure hardware";
        } else {
            secureHW = "Key is NOT inside secure hardware";
        }

        long timeElapsedGetKey = (stopGetKey - startGetKey) / 1000000;
        long timeSig = (stopSig - startSig) / 1000000;

        String s = secureHW + "\n" + "\n"
                + "Private Key: " + privateKey.toString() + "\n"
                + "Public Key: " + publicKey.toString() + "\n" + "\n"
                + "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                + "Time for signing entry '123': " + timeSig + " ms \n" + "\n"
                + "Created signature: " + signatureCreated;
        System.out.println(s);

        textApplication.setText(s);
    }

    public void signInTEE() throws Exception {
        long startGetKey = System.nanoTime();
        // The key pair can also be obtained from the Android Keystore any time as follows:
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("keyTEE", null);
        KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
        KeyInfo keyInfo = null;
        try {
            keyInfo = factory.getKeySpec(privateKey, KeyInfo.class);
        } catch (InvalidKeySpecException e) {
            // Not an Android KeyStore key.
        }
        PublicKey publicKey = keyStore.getCertificate("keyTEE").getPublicKey();

        long startSig = System.nanoTime();

        Signature signature = Signature.getInstance("SHA256withRSA/PSS");
        signature.initSign(keyPairTEE.getPrivate());

        signature.initSign(privateKey);
        signature.update((byte) 123);

        byte[] signatureCreated = signature.sign();
        long stopSig = System.nanoTime();

        long stopGetKey = System.nanoTime();
        //for ms divide by 1000000

        String secureHW = "";

        if (keyInfo.isInsideSecureHardware()) {
            secureHW = "Key is inside secure hardware";
        } else {
            secureHW = "Key is NOT inside secure hardware";
        }

        long timeElapsedGetKey = (stopGetKey - startGetKey) / 1000000;
        long timeSig = (stopSig - startSig) / 1000000;

        String s = secureHW + "\n" + "\n"
                + "Private Key: " + privateKey.toString() + "\n"
                + "Public Key: " + publicKey.toString() + "\n" + "\n"
                + "Time for obtaining key: " + timeElapsedGetKey + " ms \n"
                + "Time for signing entry '123': " + timeSig + " ms \n" + "\n"
                + "Created signature: " + signatureCreated;

        System.out.println(s);

        textApplication.setText(s);
    }

}
