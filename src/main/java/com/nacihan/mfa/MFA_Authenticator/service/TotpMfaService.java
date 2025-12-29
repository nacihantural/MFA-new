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

    /**
     * Kullanıcı için YENİ ve BENZERSİZ bir gizli anahtar (secret key) oluşturur.
     */
    public String generateNewMfaSecret() {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey(); // Bu metot DB'ye kaydetmek için String döndürür (Doğru)
    }

    /**
     * Google Authenticator uygulamasının okuyacağı QR kod URI'sini oluşturur.
     * @param secretKey Kullanıcının gizli anahtarı (String olarak)
     * @param username Kullanıcının adı
     * @return QR kod olarak kodlanacak URI string'i
     */
    /**
     * Google Authenticator uygulamasının okuyacağı QR kod URI'sini oluşturur.
     * HATA DÜZELTMESİ: Kütüphanenin bozuk URL üretmesi sorununu çözmek için
     * URL'yi manuel ve standartlara uygun olarak oluşturuyoruz.
     *
     * @param secretKey Kullanıcının gizli anahtarı (String olarak)
     * @param username Kullanıcının adı
     * @return QR kod olarak kodlanacak URI string'i
     */
    public String generateQrCodeUri(String secretKey, String username) {

        String issuer = "MFA-Project"; // Uygulama Adı

        try {
            // 'issuer' ve 'username' içindeki özel karakterleri URL formatına kodla
            // (Güvenli olması için '+' karakterini de '%20'ye çeviriyoruz)
            String encodedIssuer = URLEncoder.encode(issuer, StandardCharsets.UTF_8.toString()).replace("+", "%20");
            String encodedUsername = URLEncoder.encode(username, StandardCharsets.UTF_8.toString()).replace("+", "%20");

            // 'otpauth://totp/ISSUER:USERNAME?secret=SECRET&issuer=ISSUER'
            // formatını manuel olarak oluşturuyoruz.
            return String.format(
                    "otpauth://totp/%s:%s?secret=%s&issuer=%s",
                    encodedIssuer,
                    encodedUsername,
                    secretKey, // secretKey zaten Base32 formatındadır, tekrar kodlanmaz.
                    encodedIssuer
            );

        } catch (Exception e) {
            e.printStackTrace();
            return ""; // Hata olursa boş döner
        }
    }

    /**
     * Kullanıcının girdiği 6 haneli kodun doğru olup olmadığını kontrol eder.
     */
    public boolean isCodeValid(String secretKey, int code) {
        return gAuth.authorize(secretKey, code);
    }
//-------------------------------------------------------------------------------
    /**
     * Verilen QR Kod URI'sini (otpauth://...) bir Base64 PNG resmine dönüştürür.
     * Bu, HTML'de <img src="..."> içinde kullanılır.
     * @param qrCodeUri Oluşturulan TOTP URI'si (Metin)
     * @return data:image/png;base64,..... formatında bir Base64 string'i (Resim verisi)
     */
    public String generateQrCodeAsBase64(String qrCodeUri) {
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            // QR kodu 200x200 boyutunda oluştur
            BitMatrix bitMatrix = qrCodeWriter.encode(qrCodeUri, BarcodeFormat.QR_CODE, 200, 200);

            // BitMatrix'i bir PNG resmine çevir
            ByteArrayOutputStream pngOutputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "PNG", pngOutputStream);

            byte[] pngData = pngOutputStream.toByteArray();

            // Resmi "data:image/png;base64," ön ekiyle Base64 formatına çevir
            return "data:image/png;base64," + Base64.getEncoder().encodeToString(pngData);

        } catch (WriterException | IOException e) {
            // Hata durumunda loglama yapmak iyi bir pratiktir.
            e.printStackTrace();
            return ""; // Hata olursa boş resim döner
        }
    }
}