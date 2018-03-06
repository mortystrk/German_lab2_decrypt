package bstu.by.decrypt;

import android.os.Build;
import android.os.Environment;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import android.widget.Toast;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.json.simple.JSONArray;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    private final String fileName = "key.txt";
    private final String fileName2 = "text.txt";
    private TextView tv_encrypt_t, tv_secret_key, tv_decrypt_t;
    private File file, fileJSON;
    private SecretKeySpec secretKeySpec;
    private String secretKey, encryptText, seed;
    private byte[] key, cipherText;

    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tv_encrypt_t = findViewById(R.id.tv_cipher_text);
        tv_decrypt_t = findViewById(R.id.tv_decrypt_text);
        tv_secret_key = findViewById(R.id.tv_secret_key);
        seed = "mortystrk is a best arms warrior";

        file = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), fileName);
        fileJSON = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), fileName2);

        //readJSON();

        try {
            FileInputStream fis = new FileInputStream(file);
            key = new byte[(int) file.length()];
            fis.read(key);
            fis.close();

            FileInputStream fis2 = new FileInputStream(fileJSON);
            cipherText = new byte[(int) fileJSON.length()];
            fis2.read(cipherText);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        setupSecretKey();

        String resultText = decode();

        if (resultText == null) {
            Toast.makeText(getApplicationContext(), "Error :(", Toast.LENGTH_SHORT).show();
            return;
        }

        tv_decrypt_t.setText(resultText);
    }

    private boolean setupSecretKey() {

        secretKeySpec = null;

        try {
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(seed.getBytes());
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128, secureRandom);
            secretKeySpec = new SecretKeySpec(key, "AES");

            return true;
        } catch (NoSuchAlgorithmException e) {
            Toast.makeText(getApplicationContext(), "AES secret key spec error", Toast.LENGTH_SHORT).show();
            return false;
        }
    }

    private void readJSON() {

        JSONParser parser = new JSONParser();
        try {
            JSONObject object = (JSONObject) parser.parse(new FileReader(fileJSON));
            encryptText = object.get("cipher_text").toString();
        } catch (IOException e) {
            Log.e("FileReader", "error");
        } catch (ParseException e) {
            Log.e("JSONParser", "parse error");
        }
    }

    private String decode() {

        byte[] decodedBytes = null;
        //byte[] encodedBytes = encryptText.getBytes();
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            decodedBytes = cipher.doFinal(cipherText);

            return new String(decodedBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
