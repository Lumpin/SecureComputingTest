package com.example.securecomputingtest;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.io.OutputStreamWriter;

public class BenchmarkingResults {

    /**
     * writes Benchmarking Results into text file
     */
    public static void storeResults(String data, Context context) {

        try {
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(context.openFileOutput("config.txt", Context.MODE_PRIVATE));
            outputStreamWriter.write(data);
            outputStreamWriter.close();
        } catch (IOException e) {
            Log.e("Exception", "File write failed: " + e.toString());
        }


    }
}
