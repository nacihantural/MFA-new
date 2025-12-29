package com.nacihan.mfa.MFA_Authenticator.config;

import com.nacihan.mfa.MFA_Authenticator.model.User;
import com.nacihan.mfa.MFA_Authenticator.repository.UserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler{

    //karar vermek için veritabanına erişmemiz lazım
    private final UserRepository userRepository;

    //spring bu repoyu otomatik enjekte edecek
    public CustomAuthenticationSuccessHandler(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    //kullanıcı şifresini doğru girince bu çalışır
    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
                                        HttpServletResponse httpServletResponse,
                                        Authentication authentication) throws IOException, ServletException {

        // giriş yapan kim verisini al
        String username = authentication.getName();
        User user = userRepository.findByUsername(username);

        if(user == null){
           httpServletResponse.sendRedirect("/login?error=user_not_found");
            return;
        }

        //kullanıcı mfa kurulumu kontrol et
        if(user.getMfaSecret()==null|| user.getMfaSecret().isEmpty()){

            //mfa kurulu değil (setup sayfasına yönlendir)
           httpServletResponse.sendRedirect("/mfa-setup");
        }else {

            // MFA KURULU: Doğrulama sayfasına yönlendir (/mfa-verify)
            httpServletResponse.sendRedirect("/mfa-verify");
        }

    }
}
