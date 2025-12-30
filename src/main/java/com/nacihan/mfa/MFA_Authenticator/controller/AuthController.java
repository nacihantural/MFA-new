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
        this.mfaService = mfaService;// yeni


    }


//-----------------------------------------------------------------------------------------------------
//------------------------------------------------------------------------------------------------------



    @PostMapping("/register")
    public String registerUser(String username, String password) {


        if (userRepository.findByUsername(username) != null) {

            return "redirect:/register?error=username_exists";
        }


        String hashedPassword = passwordEncoder.encode(password);


        User newUser = new User(username, hashedPassword);



        userRepository.save(newUser);


        return "redirect:/login?success=registered";
    }


    @PostMapping("/mfa-verify")
    public String verifyMfaCode(@org.springframework.web.bind.annotation.RequestParam String code, 
                                Authentication authentication, 
                                HttpServletRequest request, 
                                Model model) { // <-- Model eklendi


        String username = authentication.getName();
        User user = userRepository.findByUsername(username);


        boolean isValid = false;
        try {

            int codeInt = Integer.parseInt(code);
            if (user.getMfaSecret() != null && mfaService.isCodeValid(user.getMfaSecret(), codeInt)) {
                isValid = true;
            }
        } catch (NumberFormatException e) {

            isValid = false;
        }

        if (!isValid) {
            model.addAttribute("error", "Girdiğiniz kod hatalı!");
            return "mfa-verify"; // Sayfa yenilenmez, verilerle geri döner -> Titreme çalışır!
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        request.getSession().setAttribute(
                HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                SecurityContextHolder.getContext()
        );

        return "redirect:/home";
    }


    //---------------------------------------------------------------------------------------------
    //----------------------------------------------------------------------------------------------


    @GetMapping("/mfa-setup")
    public String showMfaSetupPage(Authentication authentication, Model model) {

        String username = authentication.getName();
        User user = userRepository.findByUsername(username);

        if (user.getMfaSecret() != null && !user.getMfaSecret().isEmpty()) {
            return "redirect:/home";
        }

        String secretKey = mfaService.generateNewMfaSecret();
        user.setMfaSecret(secretKey);
        userRepository.save(user);



        String qrCodeUri = mfaService.generateQrCodeUri(secretKey, username);

        String qrCodeBase64 = mfaService.generateQrCodeAsBase64(qrCodeUri);

        model.addAttribute("qrCodeImage", qrCodeBase64); // URL yerine Base64 resmi
        model.addAttribute("secretKey", secretKey);

        return "mfa-setup";
    }



    @GetMapping("/login")
    public String showLoginPage()
    {
        return "login";
    }

    @GetMapping("/register")
    public String showRegisterPage()
    {
        return "register";
    }

    @GetMapping("/mfa-verify")
    public String showMfaVerifyPage(){
        return "mfa-verify";
    }


    @GetMapping("/home")
    public String showHomePage() {
        return "home"; // templates/home.html
    }
}
