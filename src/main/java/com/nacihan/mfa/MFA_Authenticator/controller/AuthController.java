package com.nacihan.mfa.MFA_Authenticator.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model; // POST istekleri için
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import com.nacihan.mfa.MFA_Authenticator.model.User;
import com.nacihan.mfa.MFA_Authenticator.repository.UserRepository;
import com.nacihan.mfa.MFA_Authenticator.service.TotpMfaService;

import jakarta.servlet.http.HttpServletRequest; // QR kodu sayfaya taşımak için

@Controller
public class AuthController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TotpMfaService mfaService; // <-- mfa için



    public AuthController(UserRepository userRepository, PasswordEncoder passwordEncoder,TotpMfaService mfaService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        //mfa için constructor güncellemesi
        this.mfaService = mfaService;// yeni


    }


//-----------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------


    /**
     * Tarayıcıdan "/register" adresine bir POST (form gönderme) isteği geldiğinde bu metot çalışır.
     * * @param username HTML formundaki 'username' alanından gelir.
     * @param password HTML formundaki 'password' alanından gelir.
     * @return Kayıt başarılıysa "/login" adresine yönlendirir.
     */
    @PostMapping("/register")
    public String registerUser(String username, String password) {

        // 1. Güvenlik: Kullanıcı adı zaten alınmış mı diye kontrol et
        if (userRepository.findByUsername(username) != null) {
            // Hata yönetimi: Şimdilik basitçe kayıt sayfasına geri dön
            // Gerçek projede "Bu kullanıcı adı alınmış" uyarısı gösterilir.
            return "redirect:/register?error=username_exists";
        }

        // 2. Güvenlik: Şifreyi ASLA düz metin kaydetme. Mutlaka hash'le.
        String hashedPassword = passwordEncoder.encode(password);

        // 3. Yeni kullanıcı nesnesini oluştur
        User newUser = new User(username, hashedPassword);
        // (mfaSecret alanı varsayılan olarak null (boş) olacaktır)

        // 4. Kullanıcıyı veritabanına kaydet
        userRepository.save(newUser);

        // 5. Kayıt başarılı. Kullanıcıyı giriş yapması için login sayfasına yönlendir.
        return "redirect:/login?success=registered";
    }

    /*
     * "/mfa-verify" formundan gelen 6 haneli kodu (POST) işler.
     * @param code HTML formundaki 'code' alanından gelir.
     */

    // @PostMapping("/mfa-verify")
    // public String verifyMfaCode(int code,Authentication authentication  ,HttpServletRequest request) {

    //     //1. giriş yapan kullanıcıyı bul
    //     String username = authentication.getName();
    //     User user = userRepository.findByUsername(username);

    //     //2. kod geçerli mi , DB deki secretkey i ve kodu servise gönder
    //     if(user.getMfaSecret()==null || !mfaService.isCodeValid(user.getMfaSecret(), code)) {
    //         //kod yanlışsa , süresi dolmuşsa veya hiç secretkey yoksa
    //         return "redirect:/mfa-verify?error";
    //     }

    //     // 3. KOD DOĞRU! MFA Başarılı.
    //     // Kullanıcının oturumunu "tamamen doğrulanmış" olarak işaretlememiz gerekiyor.

    //     // mevcut kimliği al
    //     Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    //     // oturumu güncelle (bu spring securitynin "artık bu kullanıcı yetkili" demesidir)
    //     request.getSession().setAttribute(
    //             HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
    //             SecurityContextHolder.getContext()
    //     );

    //     //4. ana sayfaya yönlendir
    //     return "redirect:/home";
    // }
      /*
     * "/mfa-verify" formundan gelen 6 haneli kodu (POST) işler.
     * @param code HTML formundaki 'code' alanından gelir.
     */
    @PostMapping("/mfa-verify")
    public String verifyMfaCode(@org.springframework.web.bind.annotation.RequestParam String code, 
                                Authentication authentication, 
                                HttpServletRequest request, 
                                Model model) { // <-- Model eklendi

        // 1. Giriş yapan kullanıcıyı bul
        String username = authentication.getName();
        User user = userRepository.findByUsername(username);

        // 2. Kod geçerli mi kontrol et
        // Not: 'code' parametresini String yaptık, int yaparsak başında '0' olan kodlarda (örn: 012345) sorun çıkabilir.
        // Bu yüzden servise gönderirken Integer.parseInt gerekebilir veya servisini String alacak şekilde güncelleyebilirsin.
        // Eğer servisin int istiyorsa: Integer.parseInt(code) kullan.
        
        // Hata durumunu kontrol edelim:
        boolean isValid = false;
        try {
            // String gelen kodu int'e çevirip servise yolluyoruz (Servisin int kabul ettiği varsayımıyla)
            int codeInt = Integer.parseInt(code);
            if (user.getMfaSecret() != null && mfaService.isCodeValid(user.getMfaSecret(), codeInt)) {
                isValid = true;
            }
        } catch (NumberFormatException e) {
            // Kullanıcı sayı yerine harf girerse burası çalışır
            isValid = false;
        }

        if (!isValid) {
            // --- DÜZELTME BURASI ---
            // Redirect YAPMIYORUZ. Modeline hatayı ekleyip sayfayı geri gönderiyoruz.
            model.addAttribute("error", "Girdiğiniz kod hatalı!"); 
            return "mfa-verify"; // Sayfa yenilenmez, verilerle geri döner -> Titreme çalışır!
        }

        // 3. KOD DOĞRU! MFA Başarılı.
        // Mevcut kimliği al
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Oturumu güncelle
        request.getSession().setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                SecurityContextHolder.getContext()
        );

        // 4. Ana sayfaya yönlendir
        return "redirect:/home";
    }


    //---------------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------------


    @GetMapping("/mfa-setup")
    public String showMfaSetupPage(Authentication authentication, Model model) {
        // ... (user, secretKey oluşturma ve kaydetme kodları aynı kalır) ...
        String username = authentication.getName();
        User user = userRepository.findByUsername(username);

        if (user.getMfaSecret() != null && !user.getMfaSecret().isEmpty()) {
            return "redirect:/home";
        }

        String secretKey = mfaService.generateNewMfaSecret();
        user.setMfaSecret(secretKey);
        userRepository.save(user);

        // --- DÜZELTME BURADA BAŞLIYOR ---

        // 4. Bu anahtara ait QR kod URL'sini oluştur
        String qrCodeUri = mfaService.generateQrCodeUri(secretKey, username);

        // 5. YENİ ADIM: URL'yi Base64 resmine dönüştür
        String qrCodeBase64 = mfaService.generateQrCodeAsBase64(qrCodeUri);

        // 6. Resim verisini ve anahtarı HTML'e gönder
        model.addAttribute("qrCodeImage", qrCodeBase64); // URL yerine Base64 resmi
        model.addAttribute("secretKey", secretKey);

        return "mfa-setup";
    }

    /**
     * Tarayıcıdan "/login" adresine bir GET isteği geldiğinde bu metot çalışır.
     * @return "login" string'ini döndürerek Spring'e "templates/login.html" dosyasını göstermesini söyler.
     */

    @GetMapping("/login")
    public String showLoginPage()
    {
        return "login";
    }
    /**
     * Tarayıcıdan "/register" adresine bir GET isteği geldiğinde bu metot çalışır.
     */
    @GetMapping("/register")
    public String showRegisterPage()
    {
        return "register";
    }
    /**
     * Şifre doğru girildikten sonra yönlendirilecek MFA doğrulama sayfası.
     */
    @GetMapping("/mfa-verify")
    public String showMfaVerifyPage(){
        return "mfa-verify";
    }

    /**
     * Tüm adımlar bittikten sonra gösterilecek ana sayfa.
     */
    @GetMapping("/home")
    public String showHomePage() {
        return "home"; // templates/home.html
    }
}
