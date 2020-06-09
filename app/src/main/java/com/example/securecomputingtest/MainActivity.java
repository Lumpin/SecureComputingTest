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
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class MainActivity extends AppCompatActivity {

    private TextView time;
    private TextView textApplication;

    private Spinner spinnerAlgo;
    private Spinner spinnerUse;
    private Spinner spinnerHw;
    private Spinner spinnerUseKey;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        spinnerAlgo = (Spinner) findViewById(R.id.spinnerAlgo);
        spinnerUse = (Spinner) findViewById(R.id.spinnerUse);
        spinnerHw = (Spinner) findViewById(R.id.spinnerHw);
        spinnerUseKey = (Spinner) findViewById(R.id.spinnerUseKey);

        ArrayAdapter<CharSequence> adapterAlgo = ArrayAdapter.createFromResource(this,
                R.array.spinner_algo, android.R.layout.simple_spinner_item);
        ArrayAdapter<CharSequence> adapterUse = ArrayAdapter.createFromResource(this,
                R.array.spinner_use, android.R.layout.simple_spinner_item);
        ArrayAdapter<CharSequence> adapterHw = ArrayAdapter.createFromResource(this,
                R.array.spinner_hw, android.R.layout.simple_spinner_item);
        ArrayAdapter<CharSequence> adapterUseKey = ArrayAdapter.createFromResource(this,
                R.array.spinner_usekey, android.R.layout.simple_spinner_item);

         adapterAlgo.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        adapterUse.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        adapterHw.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        adapterUseKey.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);

        spinnerAlgo.setAdapter(adapterAlgo);
        spinnerUse.setAdapter(adapterUse);
        spinnerHw.setAdapter(adapterHw);
        spinnerUseKey.setAdapter(adapterUseKey);

        time = (TextView) findViewById(R.id.time);
        textApplication = (TextView) findViewById(R.id.textApplication);
        Button buttonStart = (Button) findViewById(R.id.buttonStart);

        /*
            button for creating keys
         */
        buttonStart.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                String s = "";
                try {
                    {
                        if (spinnerHw.getSelectedItemPosition() == 0) {

                            if (spinnerAlgo.getSelectedItemPosition() == 0) {
                                s = CryptographySoftware.createKeysRSA(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 1) {
                                s = CryptographySoftware.createKeysAES(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 2) {
                                s = CryptographySoftware.createKeysECDSA(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 3) {
                                s = CryptographySoftware.createKeysHMAC(spinnerUse.getSelectedItemPosition());
                            }

                        } else if (spinnerHw.getSelectedItemPosition() == 1) {

                            if (spinnerAlgo.getSelectedItemPosition() == 0) {
                                s = CryptographyTee.createKeysRSA(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 1) {
                                s = CryptographyTee.createKeysAES(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 2) {
                                s = CryptographyTee.createKeysECDSA(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 3) {
                                s = CryptographyTee.createKeysHMAC(spinnerUse.getSelectedItemPosition());

                            }

                        } else if (spinnerHw.getSelectedItemPosition() == 2) {

                            if (spinnerAlgo.getSelectedItemPosition() == 0) {
                                s = CryptographySe.createKeysRSA(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 1) {
                                s = CryptographySe.createKeysAES(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 2) {
                                s = CryptographySe.createKeysECDSA(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 3) {
                                s = CryptographySe.createKeysHMAC(spinnerUse.getSelectedItemPosition());
                            }
                        }

                    }
                    time.setText(s);
                } catch (Exception e) {
                    time.setText(e.getMessage());
                }

            }
        });

        Button buttonSign = (Button) findViewById(R.id.buttonSign);

        /*
         *  button for using key
         */
        buttonSign.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                String s = "";
                try {
                    if (spinnerHw.getSelectedItemPosition() == 0) {
                        if (spinnerAlgo.getSelectedItemPosition() == 0) {
                            s = CryptographySoftware.useKeysRSA(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 1) {
                            s = CryptographySoftware.useKeysAES(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 2) {
                            s = CryptographySoftware.useKeysECDSA(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 3) {
                            s = CryptographySoftware.userKeysHMAC(spinnerUseKey.getSelectedItemPosition());
                        }

                    } else if (spinnerHw.getSelectedItemPosition() == 1) {
                        if (spinnerAlgo.getSelectedItemPosition() == 0) {
                            s = CryptographyTee.useKeysRSA(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 1) {
                            s = CryptographyTee.useKeysAES(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 2) {
                            s = CryptographyTee.useKeysECDSA(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 3) {
                            s = CryptographyTee.userKeysHMAC(spinnerUseKey.getSelectedItemPosition());
                        }

                    } else if (spinnerHw.getSelectedItemPosition() == 2) {
                        if (spinnerAlgo.getSelectedItemPosition() == 0) {
                            s = CryptographySe.useKeysRSA(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 1) {
                            s = CryptographySe.useKeysAES(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 2) {
                            s = CryptographySe.useKeysECDSA(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 3) {
                            s = CryptographySe.userKeysHMAC(spinnerUseKey.getSelectedItemPosition());
                        }
                    }
                    textApplication.setText(s);
                } catch (Exception e) {
                    Logger logger = Logger.getAnonymousLogger();
                    logger.log(Level.SEVERE, "an exception was thrown", e);
                    textApplication.setText("Application Error");
                }


            }
        });
    }

}
