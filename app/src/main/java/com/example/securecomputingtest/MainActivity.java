package com.example.securecomputingtest;

import androidx.appcompat.app.AppCompatActivity;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;

import java.util.logging.Level;
import java.util.logging.Logger;

/*
main activity starting the app
 */
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

        spinnerAlgo =  findViewById(R.id.spinnerAlgo);
        spinnerUse =  findViewById(R.id.spinnerUse);
        spinnerHw =  findViewById(R.id.spinnerHw);
        spinnerUseKey =  findViewById(R.id.spinnerUseKey);

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

        time =  findViewById(R.id.time);
        textApplication =  findViewById(R.id.textApplication);
        Button buttonStart =  findViewById(R.id.buttonStart);

        /*
            button for creating keys
         */
        buttonStart.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {
                long[] duration = new long[Parameters.RUNS];
                try {
                    {
                        if (spinnerHw.getSelectedItemPosition() == 0) {

                            if (spinnerAlgo.getSelectedItemPosition() == 0) {
                                duration = CryptographySoftware.createKeysRSA(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 1) {
                                duration = CryptographySoftware.createKeysAES(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 2) {
                               duration = CryptographySoftware.createKeysECDSA(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 3) {
                                duration = CryptographySoftware.createKeysHMAC(spinnerUse.getSelectedItemPosition());
                            }

                        } else if (spinnerHw.getSelectedItemPosition() == 1) {

                            if (spinnerAlgo.getSelectedItemPosition() == 0) {
                                duration = CryptographyTee.createKeysRSA(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 1) {
                                duration = CryptographyTee.createKeysAES(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 2) {
                                duration = CryptographyTee.createKeysECDSA(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 3) {
                                duration = CryptographyTee.createKeysHMAC(spinnerUse.getSelectedItemPosition());

                            }

                        } else if (spinnerHw.getSelectedItemPosition() == 2) {

                            if (spinnerAlgo.getSelectedItemPosition() == 0) {
                                duration = CryptographySe.createKeysRSA(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 1) {
                                duration = CryptographySe.createKeysAES(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 2) {
                                duration = CryptographySe.createKeysECDSA(spinnerUse.getSelectedItemPosition());
                            } else if (spinnerAlgo.getSelectedItemPosition() == 3) {
                                duration = CryptographySe.createKeysHMAC(spinnerUse.getSelectedItemPosition());
                            }
                        }

                    }

                    String text ="";

                       text = text + "\n " + duration[1];

                    time.setText(text);
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

            @SuppressLint("SetTextI18n")
            @Override
            public void onClick(View v) {
                long[]  duration = new long[Parameters.RUNS];
                try {
                    if (spinnerHw.getSelectedItemPosition() == 0) {
                        if (spinnerAlgo.getSelectedItemPosition() == 0) {
                            duration = CryptographySoftware.useKeysRSA(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 1) {
                            duration = CryptographySoftware.useKeysAES(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 2) {
                            duration = CryptographySoftware.useKeysECDSA(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 3) {
                            duration = CryptographySoftware.useKeysHMAC(spinnerUseKey.getSelectedItemPosition());
                        }

                    } else if (spinnerHw.getSelectedItemPosition() == 1) {
                        if (spinnerAlgo.getSelectedItemPosition() == 0) {
                            duration = CryptographyTee.useKeysRSA(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 1) {
                            duration = CryptographyTee.useKeysAES(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 2) {
                            duration = CryptographyTee.useKeysECDSA(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 3) {
                            duration = CryptographyTee.useKeysHMAC(spinnerUseKey.getSelectedItemPosition());
                        }

                    } else if (spinnerHw.getSelectedItemPosition() == 2) {
                        if (spinnerAlgo.getSelectedItemPosition() == 0) {
                            duration = CryptographySe.useKeysRSA(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 1) {
                            duration = CryptographySe.useKeysAES(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 2) {
                            duration = CryptographySe.useKeysECDSA(spinnerUseKey.getSelectedItemPosition());
                        } else if (spinnerAlgo.getSelectedItemPosition() == 3) {
                            duration = CryptographySe.useKeysHMAC(spinnerUseKey.getSelectedItemPosition());
                        }
                    }

                    String text ="";

                        text = text + "\n " + duration[1];

                    textApplication.setText(text);
                } catch (Exception e) {
                    Logger logger = Logger.getAnonymousLogger();
                    logger.log(Level.SEVERE, "an exception was thrown", e);
                    textApplication.setText("Application Error");
                }


            }
        });
    }

}
