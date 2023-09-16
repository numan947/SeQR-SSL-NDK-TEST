package com.wifiphase2.openssltest;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Bundle;
import android.provider.DocumentsContract;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.documentfile.provider.DocumentFile;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.NotFoundException;
import com.google.zxing.RGBLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.GlobalHistogramBinarizer;
import com.google.zxing.multi.qrcode.QRCodeMultiReader;
import com.wifiphase2.openssltest.databinding.ActivityMainBinding;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Calendar;
import java.util.List;


/*
* App Design:
* 1. Read qr code images from directory and parse.
* 2. Read certificates from directory and generate hash based on parsed granularity.
* 3. Match
* 4. Provide feedback to UI
* 5. Document output to a file (csv?)
*
* */

public class MainActivity extends AppCompatActivity {

    // Used to load the 'openssltest' library on application startup.
    static {
        System.loadLibrary("openssltest");
    }
    private ActivityMainBinding binding;
    public static final boolean DEBUG = false;




    // TAG947: START
    // these are the directories
    private final String certFolder = "leaf_certificates";
    private final String qrCodeFolderPref = "generated_qr_codes";
    private final String gran0String = "leaf";
    private final String gran1String = "pubkey";
    private final String sha256String = "sha256";
    private final String sha512String = "sha512";
    private final String validString = "valid";
    private final String expiredString = "expired";
    // TAG947: END



    //UI Bindings
    private TextView testCompleted;
    private TextView textFolderLocation;
    private TextView textProgressBar;
    private Button buttonFolderLocation;
    private Button buttonRuntTest;
    private Button buttonClearAll;
    private Button buttonSingleImageTest;
    private Button buttonCameraTest;
    private ProgressBar progressBar;

    private Uri folderLocation;
    private DocumentFile certFolderDocument;
    private DocumentFile gQRLS256V;
    private DocumentFile gQRLS256E;
    private DocumentFile gQRLS512V;
    private DocumentFile gQRLS512E;
    private DocumentFile gQRPS256V;
    private DocumentFile gQRPS256E;
    private DocumentFile gQRPS512V;
    private DocumentFile gQRPS512E;



    private String folderLocationStr;
    private boolean testFinished;
    private boolean stopRequested;

    // UI Related Code: START
    private void bindUIElements(){
        textFolderLocation = binding.textFolderLocation;
        textProgressBar = binding.textProgressBar;
        buttonFolderLocation = binding.buttonFolderLocation;
        buttonRuntTest = binding.buttonRunTest;
        buttonClearAll = binding.buttonClearAll;
        buttonSingleImageTest = binding.singleImageReadQrcode;
        buttonCameraTest = binding.cameraQrCodeTest;
        progressBar = binding.progressHorizontal;
        testCompleted = binding.testCompleted;

    }

    private void updateUIElements()
    {
        if(folderLocation == null) {
            textProgressBar.setText("-/-");
            testCompleted.setVisibility(View.GONE);
            progressBar.setProgress(0);

            textProgressBar.setVisibility(View.GONE);
            textFolderLocation.setText("Select A Folder Location to Start");

            progressBar.setVisibility(View.GONE);
            buttonRuntTest.setVisibility(View.GONE);
        }

        if(folderLocation != null){
            textFolderLocation.setVisibility(View.VISIBLE);
            textFolderLocation.setText(folderLocationStr);

            textProgressBar.setVisibility(View.VISIBLE);
            progressBar.setVisibility(View.VISIBLE);

            buttonRuntTest.setVisibility(View.VISIBLE);
        }
    }

    private void setupButtonActions()
    {
        buttonClearAll.setOnClickListener(view -> {
            folderLocation = null;
            testFinished = false;
            stopRequested = true;
            updateUIElements();
        });


        buttonFolderLocation.setOnClickListener(view -> {
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
            i.addCategory(Intent.CATEGORY_DEFAULT);
            directoryChooser.launch(Intent.createChooser(i, "Choose directory"));
        });


        buttonRuntTest.setOnClickListener(view -> {
            buttonRuntTest.setEnabled(false);
            new Thread(this::runAllTest).start();
        });


        buttonSingleImageTest.setOnClickListener(view->{
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT_TREE);
            i.addCategory(Intent.CATEGORY_DEFAULT);
            fileChooser.launch(Intent.createChooser(i, "Choose A Folder"));
        });
        buttonCameraTest.setOnClickListener(view->{
            Toast.makeText(this, "HELLO FROM CAMERA TEST", Toast.LENGTH_SHORT).show();
        });

    }


    ActivityResultLauncher<Intent> fileChooser = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == Activity.RESULT_OK) {
                    // There are no request codes
                    Intent data = result.getData();
                    Uri uri = data.getData();
                    Log.d("TAG947",uri.getPath());
                    Uri docUri = DocumentsContract.buildDocumentUriUsingTree(uri,  DocumentsContract.getTreeDocumentId(uri));
                    DocumentFile documentFile = DocumentFile.fromTreeUri(MainActivity.this, docUri);
                    for(DocumentFile df: documentFile.listFiles()){
                        byte[] imageBytes = readBytesFromFile(this, df.getUri());
                        System.out.println(Arrays.toString(imageBytes));
                        String qrCodeString = openImageInAssets(df.getUri());
                        System.out.println(qrCodeString);
                    }

                    //
//                    folderLocation = docUri;
//                    String[]path = docUri.getPath().split(":");
//                    folderLocationStr = path[path.length - 1];
//
//                    setupFolderUris();
//                    if(DEBUG)
//                        printAllUri();
//
//                    updateUIElements();
//                    buttonRuntTest.setEnabled(true);

                }
            });

    ActivityResultLauncher<Intent> directoryChooser = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == Activity.RESULT_OK) {
                    // There are no request codes
                    Intent data = result.getData();
                    Uri uri = data.getData();
                    Uri docUri = DocumentsContract.buildDocumentUriUsingTree(uri,  DocumentsContract.getTreeDocumentId(uri));

                    folderLocation = docUri;
                    String[]path = docUri.getPath().split(":");
                    folderLocationStr = path[path.length - 1];

                    setupFolderUris();
                    if(DEBUG)
                        printAllUri();

                    updateUIElements();
                    buttonRuntTest.setEnabled(true);

                }
            });

    // UI Related Code: END


    private void printAllUri()
    {
        System.out.println(certFolderDocument.getName());

        System.out.println(gQRLS256V.getName());
        System.out.println(gQRLS256E.getName());
        System.out.println(gQRLS512V.getName());
        System.out.println(gQRLS512E.getName());

        System.out.println(gQRPS256V.getName());
        System.out.println(gQRPS256E.getName());
        System.out.println(gQRPS512V.getName());
        System.out.println(gQRPS512E.getName());

    }
    private void setupFolderUris(){
        DocumentFile documentFile = DocumentFile.fromTreeUri(MainActivity.this, folderLocation);

        for(DocumentFile df : documentFile.listFiles()){
            if(df.isDirectory()){
                if(DEBUG)
                    System.out.println(df.getName());
                switch (df.getName()){
                    case certFolder:
                        certFolderDocument = df;
                        break;

                    case qrCodeFolderPref+"_"+gran0String+"_"+sha256String+"_"+validString:
                        gQRLS256V = df;
                        break;
                    case qrCodeFolderPref+"_"+gran0String+"_"+sha256String+"_"+expiredString:
                        gQRLS256E = df;
                        break;
                    case qrCodeFolderPref+"_"+gran0String+"_"+sha512String+"_"+validString:
                        gQRLS512V = df;
                        break;
                    case qrCodeFolderPref+"_"+gran0String+"_"+sha512String+"_"+expiredString:
                        gQRLS512E = df;
                        break;


                    case qrCodeFolderPref+"_"+gran1String+"_"+sha256String+"_"+validString:
                        gQRPS256V = df;
                        break;
                    case qrCodeFolderPref+"_"+gran1String+"_"+sha256String+"_"+expiredString:
                        gQRPS256E = df;
                        break;
                    case qrCodeFolderPref+"_"+gran1String+"_"+sha512String+"_"+validString:
                        gQRPS512V = df;
                        break;
                    case qrCodeFolderPref+"_"+gran1String+"_"+sha512String+"_"+expiredString:
                        gQRPS512E = df;
                        break;
                }
            }
        }
    }

    private Uri generateUriForFile(Uri fromUri, String appendedFileName)
    {
        Uri.Builder uriBuilder = new Uri.Builder();
        uriBuilder.scheme(fromUri.getScheme());
        uriBuilder.authority(fromUri.getAuthority());

        List<String> segments = fromUri.getPathSegments();
        for(int i=0; i<segments.size() - 1; i++)
            uriBuilder.appendPath(segments.get(i));
        uriBuilder.appendPath(segments.get(segments.size()-1) + "/"+appendedFileName+ ".png");

        return uriBuilder.build();
    }

    private void generateResultAndWriteToFile(byte[] rawCert, DocumentFile df, String certName, StringBuilder builder, PrintWriter writer)
    {
        builder.setLength(0);
        WifiQrCode qrCode;
        Uri fileUri = generateUriForFile(df.getUri(), certName);
        String qrCodeString = openImageInAssets(fileUri);
        try {
            if(qrCodeString == null){
                builder.append(fileUri.getPath()).append(",").append("NULL").append(",").append("NULL").append(",").append("NULL");
                builder.append(",").append("NULL");
                builder.append(",").append("NULL");
                if(DEBUG)
                    System.out.println(builder);
                writer.println(builder);
                return;
            }
            qrCode = new WifiQrCode(qrCodeString);
            
        }catch (IllegalArgumentException e) {
            throw e;
        }

        String profileValidity = qrCode.PROFILE_VALID  ? "VALID" : "INVALID";
        String qrType = qrCode.GRANULARITY == 0 ? "leaf_certificate" : "public_key";
        String shaValue = qrCode.HASH_CHOICE == 0 ? "SHA256" : "SHA512";
        System.out.println(fileUri.getPath());
        builder.append(fileUri.getPath()).append(",").append(qrType).append(",").append(shaValue).append(",").append(profileValidity);

        if(qrCode.PROFILE_VALID){
            builder.append(",").append("Y");
            int tmp = parseAndVerifyOpenSSLCertificate(rawCert, qrCode.GRANULARITY, qrCode.HASH_CHOICE, qrCode.HashList, convertIntegers(qrCode.cumHashSize), qrCode.cumHashSize.size());
            builder.append(",").append(tmp);
        }else{
            builder.append(",").append("N").append(",").append("N/A");
        }

        writer.println(builder);
    }


    private void runAllTest() {
        // Main entry point for running all tests
        stopRequested = false;
        if(testFinished){
            runOnUiThread(() -> Toast.makeText(MainActivity.this, "Test Finished! Clear before testing again!", Toast.LENGTH_LONG).show());
            return;
        }

        String saveFileName = java.text.DateFormat.getDateTimeInstance().format(Calendar.getInstance().getTime())+ "_AnalysisResults.csv";
        DocumentFile docFile = DocumentFile.fromTreeUri(MainActivity.this, folderLocation);
        if(docFile == null){
            runOnUiThread(() -> Toast.makeText(MainActivity.this, "Error parsing selected folder!", Toast.LENGTH_LONG).show());
            return;
        }

        DocumentFile resultFile = docFile.findFile(saveFileName);
        PrintWriter writer = null;
        if(resultFile == null)
            resultFile = docFile.createFile("text/csv", saveFileName);

        try {
            if (resultFile != null) {
                writer = new PrintWriter(new BufferedWriter(new OutputStreamWriter(getContentResolver().openOutputStream(resultFile.getUri()))));
            }else{
                runOnUiThread(() -> Toast.makeText(MainActivity.this, "Error during result file creation/find!", Toast.LENGTH_LONG).show());
                return;
            }
        } catch (FileNotFoundException e) {
            stopRequested = true;
            e.printStackTrace();
        }


        if (writer != null) {
            writer.println("CertName,QRType,ShaValue,ProfileValidity,RunTest?,TestResult");
        }else{
            runOnUiThread(() -> Toast.makeText(MainActivity.this, "Error during writer creation!", Toast.LENGTH_LONG).show());
            return;
        }

        System.out.println(certFolderDocument.getName());
        int mx = certFolderDocument.listFiles().length;
        progressBar.setMax(mx);
        int p = 0;
        int cnt = 0;


        StringBuilder resultLine = new StringBuilder();


        for(DocumentFile df : certFolderDocument.listFiles()){
            resultLine.setLength(0);

            if(stopRequested)
                break;
            if(!df.isDirectory()){ // must not be a folder
//                System.out.println(df.getUri());

                byte[] rawCert;
                rawCert = readBytesFromFile(MainActivity.this, df.getUri());

                if(rawCert == null){
                    runOnUiThread(() -> Toast.makeText(MainActivity.this, "Aborting....failed to read certificate: "+df.getName(), Toast.LENGTH_LONG).show());
                    break;
                }

                try {
                    generateResultAndWriteToFile(rawCert, gQRLS256V, df.getName(), resultLine, writer);
                    if(DEBUG) System.out.println(resultLine);

                    generateResultAndWriteToFile(rawCert, gQRLS256E, df.getName(), resultLine, writer);
                    if(DEBUG) System.out.println(resultLine);

                    generateResultAndWriteToFile(rawCert, gQRLS512V, df.getName(), resultLine, writer);
                    if(DEBUG) System.out.println(resultLine);

                    generateResultAndWriteToFile(rawCert, gQRLS512E, df.getName(), resultLine, writer);
                    if(DEBUG) System.out.println(resultLine);


                    generateResultAndWriteToFile(rawCert, gQRPS256V, df.getName(), resultLine, writer);
                    if(DEBUG) System.out.println(resultLine);
                    generateResultAndWriteToFile(rawCert, gQRPS256E, df.getName(), resultLine, writer);
                    if(DEBUG) System.out.println(resultLine);

                    generateResultAndWriteToFile(rawCert, gQRPS512V, df.getName(), resultLine, writer);
                    if(DEBUG) System.out.println(resultLine);

                    generateResultAndWriteToFile(rawCert, gQRPS512E, df.getName(), resultLine, writer);
                    if(DEBUG) System.out.println(resultLine);
                }
                catch (IllegalArgumentException e){
                    e.printStackTrace();
                    stopRequested = true;
                    runOnUiThread(() -> Toast.makeText(MainActivity.this, "Aborting....failed to parse QR code!"+df.getName(), Toast.LENGTH_LONG).show());
                    break;
                }

                p++;
                cnt++;

                int finalCnt = cnt;
                int finalP = p;
                runOnUiThread(() -> {
                    progressBar.setProgress(finalP, true);
                    textProgressBar.setText(finalCnt +"/"+mx);
                });

            }
        }
        writer.close();

        if(!stopRequested ) {
            testFinished = true;
            runOnUiThread(()->{testCompleted.setVisibility(View.VISIBLE);});
        }
        else {
            if(DEBUG)System.out.println("Stopping after: " + cnt);
            runOnUiThread(() -> Toast.makeText(MainActivity.this, "Test Stopped!", Toast.LENGTH_LONG).show());
        }

    }



    // Assumption: all folders are single level, i.e. no subfolders inside the asset folder
    private List<String> listAssetFiles(String path)
    {
        String[] list;
        try{
            list = getAssets().list(path);
            if(list.length > 0){
                return Arrays.asList(list);
            }

        }catch (IOException e){
            e.printStackTrace();
            if(DEBUG)
                System.out.println("Exception in listAssetFiles for: "+path);
        }
        return null;
    }

    public static int[] convertIntegers(List<Integer> integers)
    {
        int[] ret = new int[integers.size()];
        for (int i=0; i < ret.length; i++)
        {
            ret[i] = integers.get(i);
        }
        return ret;
    }

    public static byte[] readBytesFromFile(Context context, Uri fileUri) {

        final int bufferLength = 4 * 0x400;
        byte[]buf = new byte[bufferLength];
        int readLen;

        InputStream stream = null;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        try {
            stream = context.getContentResolver().openInputStream(fileUri);
            while((readLen = stream.read(buf, 0, bufferLength)) != -1){
                bos.write(buf, 0, readLen);
            }
            return bos.toByteArray();
        }catch (IOException e){
            System.err.println("Error during reading certificate file!");
            e.printStackTrace();
            return null;
        }finally {
            try {
                stream.close();
            } catch (IOException e) {
                System.err.println("Error during closing certificate file!");
                e.printStackTrace();
            }
        }

/*        StringBuilder sb = new StringBuilder();
        String mLine = reader.readLine();
        while (mLine != null) {
            sb.append(mLine); // process line
            mLine = reader.readLine();
        }
        reader.close();
        return sb.toString();*/
    }

    public Result parseInfoFromBitmap(Bitmap bitmap) {
        System.out.println("WIDTH: "+bitmap.getWidth()+" HEIGHT: "+bitmap.getHeight());

        int[] pixels = new int[bitmap.getWidth() * bitmap.getHeight()];
        bitmap.getPixels(pixels, 0, bitmap.getWidth(), 0, 0, bitmap.getWidth(), bitmap.getHeight());

//        Bitmap tmp = Bitmap.createScaledBitmap(bitmap, 200, 200, false);
        Bitmap tmp = bitmap;
        pixels = new int[tmp.getWidth() * tmp.getHeight()];
        tmp.getPixels(pixels, 0, tmp.getWidth(), 0, 0, tmp.getWidth(), tmp.getHeight());
        System.out.println("WIDTH: "+tmp.getWidth()+" HEIGHT: "+tmp.getHeight());

        RGBLuminanceSource source = new RGBLuminanceSource(tmp.getWidth(),
                tmp.getHeight(), pixels);
//        GlobalHistogramBinarizer binarizer = new GlobalHistogramBinarizer(source);
        BinaryBitmap image = new BinaryBitmap(new GlobalHistogramBinarizer(source));
        System.out.println(image.isCropSupported());
        Result[] result;
        try {
            result = new QRCodeMultiReader().decodeMultiple(image);
            return result[0];
        } catch (NotFoundException e) {
            e.printStackTrace();
        }
        return null;

    }

    public String openImageInAssets(Uri imageUri) {
        InputStream fileStream = null;
        try {
            fileStream =  getContentResolver().openInputStream(imageUri);

            if (fileStream != null) {
                Bitmap bitmap = BitmapFactory.decodeStream(fileStream);
                System.out.println(bitmap.toString());
                Result res = parseInfoFromBitmap(bitmap);
                if(DEBUG) {
                    System.out.println(imageUri.getPath());
                    System.out.println(res);
                }
                if(res == null)
                    return null;
                return res.toString();
            }
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        } finally {
            //Always clear and close
            try {
                if (fileStream != null) {
                    fileStream.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return null;
    }


    // ANDROID RELATED CODE: START
    @Override public void onResume() {
        super.onResume();
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
    }

    @Override public void onPause() {
        super.onPause();
        getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
    }


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        bindUIElements();
        setupButtonActions();
        updateUIElements();


    }

    public native int parseAndVerifyOpenSSLCertificate(byte[] rawCert, int granularity, int hash_choice, String hash_list, int[]cumHashSize, int cumHashSizeLen);
    // ANDROID RELATED CODE: END



}