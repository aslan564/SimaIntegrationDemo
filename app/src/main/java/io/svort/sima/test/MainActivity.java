package io.svort.sima.test;

import androidx.annotation.NonNull;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.FileProvider;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.Toast;

import com.tom_roush.pdfbox.io.IOUtils;
import com.tom_roush.pdfbox.pdmodel.PDDocument;
import com.tom_roush.pdfbox.pdmodel.PDPage;
import com.tom_roush.pdfbox.pdmodel.PDPageContentStream;
import com.tom_roush.pdfbox.pdmodel.font.PDFont;
import com.tom_roush.pdfbox.pdmodel.font.PDType1Font;
import com.tom_roush.pdfbox.util.PDFBoxResourceLoader;

import java.io.ByteArrayInputStream;
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
    private static final String EXTRA_DOCUMENT_NAME_FIELD = "document_name";
    private static final String EXTRA_CHALLENGE_FIELD = "challenge";
    private static final String EXTRA_SIGNATURE_FIELD = "signature";
    private static final String EXTRA_USER_CODE_FIELD = "user_code";
    private static final String EXTRA_REQUEST_ID_FIELD = "request_id";
    private static final String EXTRA_LOGO_FIELD = "service_logo";

    private static final int EXTRA_CLIENT_ID_VALUE = 1; // your client id
    private static final String EXTRA_SERVICE_VALUE = "Test Bank"; // service name to be displayed
    private static final String EXTRA_USER_CODE_VALUE = "1234567"; // user FIN code
    private static final String EXTRA_LOGO_VALUE = "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTI1IiBoZWlnaHQ9IjEyNSIgdmlld0JveD0iMCAwIDEyNSAxMjUiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxjaXJjbGUgY3g9IjYyLjUiIGN5PSI2Mi41IiByPSI2Mi41IiBmaWxsPSIjNjEwQkVGIi8+CjxwYXRoIGQ9Ik02Mi40MzE4IDI5LjAwMTNDNjEuOTgzMiAyOS4wMTczIDYxLjU1OTMgMjkuMTg3NiA2MS4xMzU0IDI5LjQ1NjRMMjkuODQxNyA1NC4yMTY4QzI5LjEyMiA1NC43NzI3IDI4LjgxNDUgNTUuODE1NyAyOS4xMTM5IDU2LjY3NDdDMjkuNDEzMyA1Ny41MzM2IDMwLjI5NzIgNTguMTQzNyAzMS4yMDYyIDU4LjEzMTFIMzcuMDI4M1Y4NS44MDQ1SDMxLjIwNjJDMzAuMDE1NyA4NS44MDQ1IDI5LjA0NjkgODcuMDY4NiAyOS4wMjI5IDg3Ljk4OTNWOTMuODE1M0MyOS4wMjMgOTQuOTU5MiAzMC4wNjMxIDk1Ljk5OTkgMzEuMjA2MiA5Nkg5My43OTM4Qzk0LjkzNjkgOTUuOTk5OSA5NS45NzcgOTQuOTU5MiA5NS45NzcxIDkzLjgxNTNWODcuOTg5M0M5NS45NzcgODYuODQ1MyA5NC45MzY5IDg1LjgwNDcgOTMuNzkzOCA4NS44MDQ1SDg5LjQyNzJWNTguMTMxMUg5My43OTM4Qzk0LjcwMjggNTguMTQzNSA5NS41ODY3IDU3LjUzMzYgOTUuODg2MSA1Ni42NzQ3Qzk2LjE4NTUgNTUuODE1NyA5NS44NzggNTQuNzcyNyA5NS4xNTgzIDU0LjIxNjhMNjMuODY0NiAyOS40NTY0QzYzLjM1MzUgMjkuMTIzMiA2Mi44ODAzIDI4Ljk4NTIgNjIuNDMxOCAyOS4wMDEzWk02Mi41IDMzLjk2MjRMODcuNTE2OCA1My43NjE3SDM3LjQ4MzFMNjIuNSAzMy45NjI0Wk02Mi41IDM5LjkyNUM1OS4zMTA0IDM5LjkyNSA1Ni42Nzc5IDQyLjU1OTIgNTYuNjc3OSA0NS43NTA5QzU2LjY3NzkgNDguOTQyNiA1OS4zMTA0IDUxLjU3NjkgNjIuNSA1MS41NzY5QzY1LjY4OTYgNTEuNTc2OSA2OC4zMjIxIDQ4Ljk0MjYgNjguMzIyMSA0NS43NTA5QzY4LjMyMjEgNDIuNTU5MiA2NS42ODk1IDM5LjkyNSA2Mi41IDM5LjkyNVpNNjIuNSA0NC4yOTQ0QzYzLjMyOTcgNDQuMjk0NCA2My45NTU1IDQ0LjkyMDYgNjMuOTU1NSA0NS43NTA5QzYzLjk1NTUgNDYuNTgxMiA2My4zMjk3IDQ3LjIwNzQgNjIuNSA0Ny4yMDc0QzYxLjY3MDMgNDcuMjA3NCA2MS4wNDQ0IDQ2LjU4MTIgNjEuMDQ0NCA0NS43NTA5QzYxLjA0NDQgNDQuOTIwNiA2MS42NzAyIDQ0LjI5NDQgNjIuNSA0NC4yOTQ0Wk00MS4zOTQ4IDU4LjEzMTFINDIuODUwNFY4NS44MDQ1SDQxLjM5NDhWNTguMTMxMVpNNDcuMjE2OSA1OC4xMzExSDc5LjIzODVWODUuODA0NUg0Ny4yMTY5VjU4LjEzMTFaTTgzLjYwNTEgNTguMTMxMUg4NS4wNjA2Vjg1LjgwNDVIODMuNjA1MVY1OC4xMzExWk02Mi40NzcyIDYwLjMxNTlDNjEuNTQ1IDYwLjMxNTkgNjAuNjc0MiA2MC45NDczIDYwLjQwNzYgNjEuODQwN0w1OC44NjEyIDY2Ljg3MDFINTQuNDk0Nkw1Mi45NDgxIDYxLjg0MDdDNTIuNjgxIDYwLjkyODggNTEuNzYwMSA2MC4zMjAyIDUwLjgxMDMgNjAuMzM4NkM0OS40NDUgNjAuMzU2MSA0OC4zMzY5IDYxLjg0MDUgNDguNzYzNSA2My4xMzc5TDQ5LjkyMzQgNjYuODkyOEM0OC44MTY5IDY2Ljk5OTQgNDcuOTQ0NyA2Ny45MjAyIDQ3Ljk0NDcgNjkuMDU0OEM0Ny45NDQ3IDcwLjI2MDkgNDguOTIyMiA3MS4yMzk2IDUwLjEyOCA3MS4yMzk2SDUxLjI2NTJMNTEuNjk3MyA3Mi42OTZINTEuNTgzNkM1MC4zNzc4IDcyLjY5NiA0OS40MDAzIDczLjY3NDcgNDkuNDAwMyA3NC44ODA4QzQ5LjQwMDMgNzYuMDg2OCA1MC4zNzc4IDc3LjA2NTUgNTEuNTgzNiA3Ny4wNjU1SDUzLjAzOTFMNTQuNTg1NiA4Mi4wNDk1QzU0Ljg1MjIgODIuOTQyOSA1NS43NDU3IDgzLjYxOTggNTYuNjc3OSA4My42MTk4QzU3LjYxMDEgODMuNjE5OCA1OC41MDM2IDgyLjk0MjkgNTguNzcwMiA4Mi4wNDk1TDYwLjMxNjcgNzcuMDY1NUg2NC42ODMzTDY2LjIyOTggODIuMDQ5NUM2Ni40OTY0IDgyLjk0MjkgNjcuMzg5OSA4My42MTk4IDY4LjMyMjEgODMuNjE5OEM2OS4yNTQzIDgzLjYxOTggNzAuMTQ3OCA4Mi45NDI5IDcwLjQxNDQgODIuMDQ5NUw3MS45NjA5IDc3LjA2NTVINzMuNDE2NEM3NC42MjIyIDc3LjA2NTUgNzUuNTk5NyA3Ni4wODY4IDc1LjU5OTcgNzQuODgwOEM3NS41OTk3IDczLjY3NDcgNzQuNjIyMiA3Mi42OTYgNzMuNDE2NCA3Mi42OTZINzMuMzAyN0w3My43MzQ4IDcxLjIzOTZINzQuODcyQzc2LjA3NzggNzEuMjM5NiA3Ny4wNTUzIDcwLjI2MDkgNzcuMDU1MyA2OS4wNTQ4Qzc3LjA1NTMgNjcuOTIwMiA3Ni4xODMxIDY2Ljk5OTQgNzUuMDc2NiA2Ni44OTI4TDc2LjIzNjUgNjMuMTM3OUM3Ni41NzU5IDYyLjA0MjEgNzUuODYwMiA2MC44NDA2IDc0Ljc4MSA2MC40NTI0QzczLjY1MjIgNjAuMDQ2NCA3Mi4zOTEzIDYwLjc0NDkgNzIuMDUxOSA2MS44NDA3TDcwLjUwNTQgNjYuODcwMUg2Ni4xMzg4TDY0LjU5MjMgNjEuODQwN0M2NC4zMjU3IDYwLjk0NzMgNjMuNDA5NCA2MC4zMTU5IDYyLjQ3NzMgNjAuMzE1OUg2Mi40NzcyWk01NS44MzY0IDcxLjIzOTZINTcuNTE5M0w1Ny4wNjQ1IDcyLjY5Nkg1Ni4yOTEyTDU1LjgzNjQgNzEuMjM5NlpNNjIuMDkwNiA3MS4yMzk2SDYyLjkwOTNMNjMuMzQxNCA3Mi42OTZINjEuNjU4NUw2Mi4wOTA2IDcxLjIzOTZaTTY3LjQ4MDYgNzEuMjM5Nkg2OS4xNjM1TDY4LjcwODcgNzIuNjk2SDY3LjkzNTRMNjcuNDgwNiA3MS4yMzk2Wk0zMy4zODk1IDkwLjE3NEg5MS42MTA1VjkxLjYzMDVIMzMuMzg5NVY5MC4xNzRaIiBmaWxsPSIjRkNGQ0ZDIi8+Cjwvc3ZnPg=="; // service logo to be displayed

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
                    if (result.getResultCode() == Activity.RESULT_OK) {
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
                                Uri documentUri = result.getData().getData();

                                this.signPDF(documentUri, intent);
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                            Toast.makeText(this, "Open intent error", Toast.LENGTH_LONG).show();
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

                            byte[] signedChallenge = intent.getByteArrayExtra("signed");
                            byte[] certBytes = intent.getByteArrayExtra("certificate");

                            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            InputStream certStream = new ByteArrayInputStream(certBytes);
                            X509Certificate certificate = (X509Certificate) cf.generateCertificate(certStream);

                            Signature s = Signature.getInstance(SIMA_SIGNATURE_ALGORITHM);
                            s.initVerify(certificate);
                            s.update(this.challenge);

                            if (s.verify(signedChallenge)) {
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

    public void signChallenge(View view) throws NoSuchAlgorithmException, InvalidKeyException {
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

            intent = intent.setAction(SIGN_CHALLENGE_ACTION)
                    .setFlags(0)
                    .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
                    .putExtra(EXTRA_CHALLENGE_FIELD, challenge)
                    .putExtra(EXTRA_SERVICE_FIELD, EXTRA_SERVICE_VALUE)
                    .putExtra(EXTRA_CLIENT_ID_FIELD, EXTRA_CLIENT_ID_VALUE)
                    .putExtra(EXTRA_SIGNATURE_FIELD, signature)
                    .putExtra(EXTRA_LOGO_FIELD, EXTRA_LOGO_VALUE)
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
                .setType("application/pdf")
                .addCategory(Intent.CATEGORY_OPENABLE);

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
        Cursor cursor = getContentResolver().query(documentUri, null, null, null, null);
        cursor.moveToFirst();
        int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
        this.filename = cursor.getString(nameIndex);

        cursor.close();

        InputStream stream = getContentResolver().openInputStream(documentUri);
        byte[] documentBytes = IOUtils.toByteArray(stream);

        MessageDigest md = MessageDigest.getInstance(CLIENT_HASH_ALGORITHM);
        md.update(documentBytes);
        byte[] fileHash = md.digest();

        Mac mac = Mac.getInstance(CLIENT_SIGNATURE_ALGORITHM);
        mac.init(new SecretKeySpec(CLIENT_MASTER_KEY.getBytes(), CLIENT_SIGNATURE_ALGORITHM));
        byte[] signature = mac.doFinal(fileHash);

        String uuid = UUID.randomUUID().toString();

        intent = intent.setAction(SIGN_PDF_ACTION)
                .setFlags(0)
                .setData(documentUri)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                .putExtra(EXTRA_DOCUMENT_NAME_FIELD, this.filename)
                .putExtra(EXTRA_SERVICE_FIELD, EXTRA_SERVICE_VALUE)
                .putExtra(EXTRA_CLIENT_ID_FIELD, EXTRA_CLIENT_ID_VALUE)
                .putExtra(EXTRA_SIGNATURE_FIELD, signature)
                .putExtra(EXTRA_USER_CODE_FIELD, EXTRA_USER_CODE_VALUE)
                .putExtra(EXTRA_LOGO_FIELD, EXTRA_LOGO_VALUE)
                .putExtra(EXTRA_REQUEST_ID_FIELD, uuid);

        this.signPdfActivityResultLauncher.launch(intent);
    }
}