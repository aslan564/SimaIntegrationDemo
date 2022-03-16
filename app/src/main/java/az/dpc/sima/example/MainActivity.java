package az.dpc.sima.example;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.AssetManager;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.view.View;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.FileProvider;

import com.tom_roush.pdfbox.android.PDFBoxResourceLoader;
import com.tom_roush.pdfbox.io.IOUtils;
import com.tom_roush.pdfbox.pdmodel.PDDocument;
import com.tom_roush.pdfbox.pdmodel.PDPage;
import com.tom_roush.pdfbox.pdmodel.PDPageContentStream;
import com.tom_roush.pdfbox.pdmodel.font.PDFont;
import com.tom_roush.pdfbox.pdmodel.font.PDType1Font;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity {

    private static final String PACKAGE_NAME = "az.dpc.sima";
    private static final String SIGN_PDF_ACTION = "sima.sign.pdf"; // action type to sign pdf
    private static final String SIGN_CHALLENGE_ACTION = "sima.sign.challenge"; // action type to sign challenge

    private static final String SIMA_SIGNATURE_ALGORITHM = "SHA256withECDSA";
    private static final String CLIENT_SIGNATURE_ALGORITHM = "HmacSHA256";
    private static final String CLIENT_HASH_ALGORITHM = "SHA-256";
    private static final String CLIENT_MASTER_KEY = "client_master_key"; // your master key

    // Intent field names
    private static final String EXTRA_CLIENT_ID_FIELD = "client_id";
    private static final String EXTRA_SERVICE_FIELD = "service_name";
    private static final String EXTRA_CHALLENGE_FIELD = "challenge";
    private static final String EXTRA_SIGNATURE_FIELD = "signature";
    private static final String EXTRA_USER_CODE_FIELD = "user_code";
    private static final String EXTRA_REQUEST_ID_FIELD = "request_id";
    private static final String EXTRA_LOGO_FIELD = "service_logo";

    private static final int EXTRA_CLIENT_ID_VALUE = 1; // your client id
    private static final String EXTRA_SERVICE_VALUE = "Test Bank"; // service name to be displayed
    private static final String EXTRA_USER_CODE_VALUE = "1234567"; // user FIN code

    ActivityResultLauncher<Intent> pickPdfActivityResultLauncher;
    ActivityResultLauncher<Intent> signPdfActivityResultLauncher;
    ActivityResultLauncher<Intent> pickDirectoryResultLauncher;
    ActivityResultLauncher<Intent> signChallengeActivityResultLauncher;

    String filename;
    Uri fileToSave;
    byte[] challenge;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        this.pickPdfActivityResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    if (result.getResultCode() == Activity.RESULT_OK && result.getData() != null) {
                        Uri documentUri = result.getData().getData();

                        if (documentUri != null) {
                        try {
                            Intent intent = getPackageManager().getLaunchIntentForPackage(PACKAGE_NAME);

                            if (intent == null) {
                                try {
                                    intent = new Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=" + PACKAGE_NAME));
                                } catch (Exception e) {
                                    intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=" + PACKAGE_NAME));
                                }

                                startActivity(intent);
                            } else {
                                this.signPDF(documentUri, intent);
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                            Toast.makeText(this, "Open intent error", Toast.LENGTH_LONG).show();
                        }
                    }
                    }
                });

        this.signPdfActivityResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    try {
                        if (result.getResultCode() == Activity.RESULT_OK) {
                            Intent intent = result.getData();

                            if (intent == null) {
                                Toast.makeText(this, "Empty response", Toast.LENGTH_LONG).show();
                                return;
                            }

                            String status = intent.getStringExtra("status");
                            String message = intent.getStringExtra("message");

                            if (status == null || !status.equals("success")) {
                                Toast.makeText(this, message, Toast.LENGTH_LONG).show();
                                return;
                            }

                            this.fileToSave = intent.getData();

                            Intent intentDirectory = new Intent(Intent.ACTION_CREATE_DOCUMENT)
                                    .addCategory(Intent.CATEGORY_OPENABLE)
                                    .setType("application/pdf")
                                    .putExtra(Intent.EXTRA_TITLE, this.filename);

                            this.pickDirectoryResultLauncher.launch(intentDirectory);
                        } else if (result.getResultCode() == Activity.RESULT_CANCELED) {
                            Toast.makeText(this, "User canceled the request", Toast.LENGTH_LONG).show();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        Toast.makeText(this, "Parse results error", Toast.LENGTH_LONG).show();
                    }
                });

        this.pickDirectoryResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    try {
                        if (result.getResultCode() == Activity.RESULT_OK) {
                            Intent intent = result.getData();

                            if (intent == null) {
                                Toast.makeText(this, "No directory chosen", Toast.LENGTH_LONG).show();
                                return;
                            }

                            OutputStream out = getContentResolver().openOutputStream(intent.getData());
                            InputStream in = getContentResolver().openInputStream(this.fileToSave);

                            if (out == null || in == null) {
                                Toast.makeText(this, "Error saving file", Toast.LENGTH_LONG).show();
                                return;
                            }

                            IOUtils.copy(in, out);

                            in.close();
                            out.close();

                            Toast.makeText(this, "File successfully signed", Toast.LENGTH_LONG).show();
                        } else if (result.getResultCode() == Activity.RESULT_CANCELED) {
                            Toast.makeText(this, "No directory chosen", Toast.LENGTH_LONG).show();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        Toast.makeText(this, "Error saving file", Toast.LENGTH_LONG).show();
                    }
                });

        this.signChallengeActivityResultLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    try {
                        if (result.getResultCode() == Activity.RESULT_OK) {
                            Intent intent = result.getData();

                            if (intent == null) {
                                Toast.makeText(this, "Empty response", Toast.LENGTH_LONG).show();
                                return;
                            }

                            String status = intent.getStringExtra("status");
                            String message = intent.getStringExtra("message");

                            if (status == null || !status.equals("success")) {
                                Toast.makeText(this, message, Toast.LENGTH_LONG).show();
                                return;
                            }

                            byte[] signatureBytes = intent.getByteArrayExtra("signature");
                            byte[] certificateBytes = intent.getByteArrayExtra("certificate");

                            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            InputStream certStream = new ByteArrayInputStream(certificateBytes);
                            X509Certificate certificate = (X509Certificate) cf.generateCertificate(certStream);

                            Signature s = Signature.getInstance(SIMA_SIGNATURE_ALGORITHM);
                            s.initVerify(certificate);
                            s.update(this.challenge);

                            if (s.verify(signatureBytes)) {
                                Principal subject = certificate.getSubjectDN();

                                Toast.makeText(this, subject.toString(), Toast.LENGTH_LONG).show();
                            } else {
                                Toast.makeText(this, "Wrong signature", Toast.LENGTH_LONG).show();
                            }
                        } else if (result.getResultCode() == Activity.RESULT_CANCELED) {
                            Toast.makeText(this, "User canceled the request", Toast.LENGTH_LONG).show();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                        Toast.makeText(this, "Parse result error", Toast.LENGTH_LONG).show();
                    }
                });

        PDFBoxResourceLoader.init(getApplicationContext());
    }

    public void pickSignPDF(View view) {
        if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, 101);
        } else {
            startPickIntent();
        }
    }

    public void signChallenge(View view) throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        Intent intent = getPackageManager().getLaunchIntentForPackage(PACKAGE_NAME);

        if (intent == null) {
            try {
                intent = new Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=" + PACKAGE_NAME));
            } catch (Exception e) {
                intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=" + PACKAGE_NAME));
            }
        } else {
            SecureRandom random = new SecureRandom();
            this.challenge = new byte[64];
            random.nextBytes(this.challenge);

            MessageDigest md = MessageDigest.getInstance(CLIENT_HASH_ALGORITHM);
            md.update(this.challenge);
            byte[] hash = md.digest();

            Mac mac = Mac.getInstance(CLIENT_SIGNATURE_ALGORITHM);
            mac.init(new SecretKeySpec(CLIENT_MASTER_KEY.getBytes(), CLIENT_SIGNATURE_ALGORITHM));
            byte[] signature = mac.doFinal(hash);

            String uuid = UUID.randomUUID().toString();
            String logo = getLogo();

            intent = intent.setAction(SIGN_CHALLENGE_ACTION)
                    .setFlags(0)
                    .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
                    .putExtra(EXTRA_CHALLENGE_FIELD, this.challenge)
                    .putExtra(EXTRA_SERVICE_FIELD, EXTRA_SERVICE_VALUE)
                    .putExtra(EXTRA_CLIENT_ID_FIELD, EXTRA_CLIENT_ID_VALUE)
                    .putExtra(EXTRA_SIGNATURE_FIELD, signature)
                    .putExtra(EXTRA_LOGO_FIELD, logo)
                    .putExtra(EXTRA_REQUEST_ID_FIELD, uuid);
        }

        this.signChallengeActivityResultLauncher.launch(intent);
    }

    public void createSignPDF(View view) {
        try {
            Intent intent = getPackageManager().getLaunchIntentForPackage(PACKAGE_NAME);

            if (intent == null) {
                try {
                    intent = new Intent(Intent.ACTION_VIEW, Uri.parse("market://details?id=" + PACKAGE_NAME));
                } catch (Exception e) {
                    intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://play.google.com/store/apps/details?id=" + PACKAGE_NAME));
                }

                startActivity(intent);
            } else {
                File file = new File(this.getFilesDir(), "test.pdf");

                if (!file.exists()) {
                    this.createPDF(this.getFilesDir() + "/test.pdf");
                }

                Uri documentUri = FileProvider.getUriForFile(this, this.getPackageName() + ".fileprovider", file);

                this.signPDF(documentUri, intent);
            }
        } catch (Exception e) {
            e.printStackTrace();
            Toast.makeText(this, "Create pdf error", Toast.LENGTH_LONG).show();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);

        if (requestCode == 101) {
            if (grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                startPickIntent();
            } else {
                Toast.makeText(this, "Storage permission denied", Toast.LENGTH_LONG).show();
            }
        }
    }

    private void startPickIntent() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT)
                .setType("application/pdf");

        this.pickPdfActivityResultLauncher.launch(intent);
    }

    private void createPDF(String path) throws IOException {
        PDDocument document = new PDDocument();
        PDPage page = new PDPage();
        document.addPage(page);

        PDFont font = PDType1Font.HELVETICA_BOLD;

        PDPageContentStream contentStream = new PDPageContentStream(document, page);

        contentStream.beginText();
        contentStream.setFont(font, 12);
        contentStream.newLineAtOffset(100, 700);
        contentStream.showText("Test PDF");
        contentStream.endText();

        contentStream.close();

        document.save(path);
        document.close();
    }

    private void signPDF(Uri documentUri, Intent intent) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        InputStream stream = getContentResolver().openInputStream(documentUri);
        byte[] documentBytes = IOUtils.toByteArray(stream);

        MessageDigest md = MessageDigest.getInstance(CLIENT_HASH_ALGORITHM);
        md.update(documentBytes);
        byte[] documentHash = md.digest();

        Mac mac = Mac.getInstance(CLIENT_SIGNATURE_ALGORITHM);
        mac.init(new SecretKeySpec(CLIENT_MASTER_KEY.getBytes(), CLIENT_SIGNATURE_ALGORITHM));
        byte[] documentSignature = mac.doFinal(documentHash);

        String uuid = UUID.randomUUID().toString();
        String logo = getLogo();

        intent = intent
                .setAction(SIGN_PDF_ACTION)
                .setFlags(0)
                .setData(documentUri)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)

                .putExtra(EXTRA_SIGNATURE_FIELD, documentSignature)

                .putExtra(EXTRA_USER_CODE_FIELD, EXTRA_USER_CODE_VALUE)
                .putExtra(EXTRA_CLIENT_ID_FIELD, EXTRA_CLIENT_ID_VALUE)
                .putExtra(EXTRA_SERVICE_FIELD, EXTRA_SERVICE_VALUE)
                .putExtra(EXTRA_LOGO_FIELD, logo)
                .putExtra(EXTRA_REQUEST_ID_FIELD, uuid);

        this.signPdfActivityResultLauncher.launch(intent);
    }

    private String getLogo() throws IOException {
        AssetManager assetManager = getAssets();
        InputStream logoFile = assetManager.open("logo.png");
        Bitmap bitmap = BitmapFactory.decodeStream(logoFile);
        logoFile.close();

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        bitmap.compress(Bitmap.CompressFormat.PNG, 100, byteArrayOutputStream);
        byte[] byteArray = byteArrayOutputStream.toByteArray();

        return "data:image/jpeg;base64," + Base64.encodeToString(byteArray, Base64.NO_PADDING);
    }
}