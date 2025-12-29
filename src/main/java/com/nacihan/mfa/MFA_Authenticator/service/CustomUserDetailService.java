package com.nacihan.mfa.MFA_Authenticator.service;

import com.nacihan.mfa.MFA_Authenticator.model.User;
import com.nacihan.mfa.MFA_Authenticator.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;


@Service // spring e bunun bir service bileşeni olduğunu söyler
public class CustomUserDetailService implements UserDetailsService {

    //veritabanına erişmek için repoyu buraya çağırıyoruz
    private  final UserRepository userRepository;

    //spring, bu sınıfı oluştururken userrepository i otomatik olarak buraya enjekte edecek (Dependency Injection)
    public CustomUserDetailService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // Spring Security, kullanıcı adıyla giriş yapılmaya çalışıldığında bu metodu çağıracak

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //kullanıcıyı veritabanında ara
        User user = userRepository.findByUsername(username);

        //kullanıcı bulamazsa hata fırlat (spring security bu hatayı yakalar )

        if(user == null){
            throw new UsernameNotFoundException("User Not Found: "+username);
        }

        // kullanıcı bulunduysa, Spring Security nin anladığı formata dönüştür
        //Bizim User nesnemizi spring in UserDetails nesnesine çeviriyoruz
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                Collections.emptyList()
        );
    }


}
