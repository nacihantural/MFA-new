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


    private final UserRepository userRepository;


    public CustomAuthenticationSuccessHandler(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
                                        HttpServletResponse httpServletResponse,
                                        Authentication authentication) throws IOException, ServletException {


        String username = authentication.getName();
        User user = userRepository.findByUsername(username);

        if(user == null){
           httpServletResponse.sendRedirect("/login?error=user_not_found");
            return;
        }


        if(user.getMfaSecret()==null|| user.getMfaSecret().isEmpty()){


           httpServletResponse.sendRedirect("/mfa-setup");
        }else {


            httpServletResponse.sendRedirect("/mfa-verify");
        }

    }
}
