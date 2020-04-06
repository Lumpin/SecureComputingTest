package com.example.securecomputingtest;

import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.view.View;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.Switch;
import android.widget.TextView;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

public class MainActivity extends AppCompatActivity {

    private TextView time;
    private Button buttonStart;
    private Switch switchSE;
    private Switch switchTEE;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        time = (TextView) findViewById(R.id.time);
        buttonStart = (Button) findViewById(R.id.buttonStart);
        switchSE = (Switch) findViewById(R.id.switchSE);
        switchTEE = (Switch) findViewById(R.id.switchTEE);

        buttonStart.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {

                if (switchSE.isChecked()) {
                    try {
                        saveInSE();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else if (switchTEE.isChecked()) {
                    try {
                        saveInTEE();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                } else {
                    try {
                        saveStandard();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        });

        switchSE.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                switchTEE.setChecked(false);
            }
        });

        switchTEE.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
                switchSE.setChecked(false);
            }
        });
    }

    public void saveInSE() {
        long start = System.nanoTime();

        try {

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

            keyPairGenerator.initialize(
                    new KeyGenParameterSpec.Builder(
                            "key1",
                            KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                            .setIsStrongBoxBacked(true)
                            .build());

            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Signature signature = Signature.getInstance("SHA256withRSA/PSS");
            signature.initSign(keyPair.getPrivate());


            // The key pair can also be obtained from the Android Keystore any time as follows:
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            PrivateKey privateKey = (PrivateKey) keyStore.getKey("key1", null);
            KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo = null;
            try {
                keyInfo = factory.getKeySpec(privateKey, KeyInfo.class);
            } catch (InvalidKeySpecException e) {
                // Not an Android KeyStore key.
            }

            PublicKey publicKey = keyStore.getCertificate("key1").getPublicKey();


            long finish = System.nanoTime();
            //for ms divide by 1000000
            long timeElapsed = (finish - start)/1000000;

            String secureHW = "";
            if(keyInfo.isInsideSecureHardware()) {
                secureHW = "Key is inside secure hardware";
            }else
            {
                secureHW = "Key is NOT inside secure hardware";
            }

            time.setText("Execution Time for SE: " + timeElapsed + " ms" + "\n" + secureHW);
        } catch (Exception e) {
            e.printStackTrace();
            time.setText("Execution Time for SE: StrongBox unavailable");
        }
    }

    public void saveInTEE() throws Exception{

        long start = System.nanoTime();

        KeyPairGenerator keyPairGenerator = null;

            keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

        keyPairGenerator.initialize(
                new KeyGenParameterSpec.Builder(
                        "key1",
                        KeyProperties.PURPOSE_SIGN)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                        .setIsStrongBoxBacked(false)
                        .build());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        Signature signature = Signature.getInstance("SHA256withRSA/PSS");
        signature.initSign(keyPair.getPrivate());


        // The key pair can also be obtained from the Android Keystore any time as follows:
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);

        PrivateKey privateKey = (PrivateKey) keyStore.getKey("key1", null);
        KeyFactory factory = KeyFactory.getInstance(privateKey.getAlgorithm(), "AndroidKeyStore");
        KeyInfo keyInfo = null;
        try {
            keyInfo = factory.getKeySpec(privateKey, KeyInfo.class);
        } catch (InvalidKeySpecException e) {
            // Not an Android KeyStore key.
        }
        PublicKey publicKey = keyStore.getCertificate("key1").getPublicKey();


        long finish = System.nanoTime();
        //for ms divide by 1000000
        long timeElapsed = (finish - start)/1000000;

        String secureHW = "";
        if(keyInfo.isInsideSecureHardware()) {
            secureHW = "Key is inside secure hardware";
        }else
        {
            secureHW = "Key is NOT inside secure hardware";
        }

        time.setText("Execution Time for TEE: " + timeElapsed + " ms" + "\n" + secureHW);
    }


    public void saveStandard() throws Exception {

        long start = System.nanoTime();

        long finish = System.nanoTime();
        //for ms divide by 1000000
        long timeElapsed = (finish - start)/1000000;
        time.setText("Execution Time for software-only: " + timeElapsed + " ms");

    }

}
