package com.example.securecomputingtest;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;

public class BenchmarkingResults {

    /**
     * writes Benchmarking Results into text file
     */
    public static void storeResults(long[] data, String name) {

        try {
//Environment.getExternalStorageDirectory() + "/" +
            String path = Environment.getExternalStorageDirectory().getAbsolutePath() +"/";
            // Create the parent path
            File dir = new File(path);
            if (!dir.exists()) {
                dir.mkdirs();
            }

            String fullName = path + name + ".txt";
            File file = new File(fullName);


            FileWriter fw = new FileWriter(file);
            BufferedWriter outputStreamWriter = new BufferedWriter(fw);


            for (int i = 0; i < data.length; i++) {
                outputStreamWriter.write(String.valueOf(data[i]) + '\n');

            }

            outputStreamWriter.close();
        } catch (IOException e) {
            Log.e("Exception", "File write failed: " + e.toString());
        }


    }
}
