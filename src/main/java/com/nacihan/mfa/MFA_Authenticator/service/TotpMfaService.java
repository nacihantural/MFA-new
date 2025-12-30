package com.nacihan.mfa.MFA_Authenticator.service; // Paket adınız bu

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.springframework.stereotype.Service;

//------------------ QR kod importları
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;

@Service
public class TotpMfaService {

    private final GoogleAuthenticator gAuth;

    public TotpMfaService() {
        this.gAuth = new GoogleAuthenticator();
    }


    public String generateNewMfaSecret() {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey();
    }


    public String generateQrCodeUri(String secretKey, String username) {

        String issuer = "MFA-Project"; // Uygulama Adı

        try {

            String encodedIssuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8.toString()).replace("+", "%20");
            String encodedUsername = URLEncoder.encode(username, StandardCharsets.UTF_8.toString()).replace("+", "%20");


            return String.format(
                    "otpauth://totp/%s:%s?secret=%s&issuer=%s",
                    encodedIssuer,
                    encodedUsername,
                    secretKey,
                    encodedIssuer
            );

        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }


    public boolean isCodeValid(String secretKey, int code) {
        return gAuth.authorize(secretKey, code);
    }
//-------------------------------------------------------------------------------

    public String generateQrCodeAsBase64(String qrCodeUri) {
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            // QR kodu 200x200 boyutunda oluştur
            BitMatrix bitMatrix = qrCodeWriter.encode(qrCodeUri, BarcodeFormat.QR_CODE, 200, 200);


            ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);

            byte[] pngData = pngOutputStream.toByteArray();

            return "data:image/png;base64," + Base64.getEncoder().encodeToString(pngData);

        } catch (WriterException | IOException e) {
            e.printStackTrace();
            return "";
        }
    }
}