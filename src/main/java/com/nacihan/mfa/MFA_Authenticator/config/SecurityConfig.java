package com.nacihan.mfa.MFA_Authenticator.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * Spring Security Yapılandırma Sınıfı.
 * Bu sınıf, uygulamanın kimlik doğrulama ve yetkilendirme kurallarını tanımlar.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // İstek sınırlama filtresini enjekte ediyoruz
    @Autowired
    private RateLimitingFilter rateLimitFilter;

    // Başarılı giriş sonrası yönlendirmeyi yöneten bileşen
    private final CustomAuthenticationSuccessHandler successHandler;

    public SecurityConfig(CustomAuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    /**
     * Güvenlik Filtre Zinciri (Security Filter Chain) Yapılandırması.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. ADIM: CSRF Korumasını Devre Dışı Bırakma (Test Amaçlı)
                // Python script'i gibi harici araçlarla POST isteği atabilmek için
                // test ortamında CSRF'i kapatıyoruz. Gerçek ortamda token kullanılmalıdır.
                .csrf(AbstractHttpConfigurer::disable)

                // 2. ADIM: RateLimitingFilter'ı Filtre Zincirinin En Başına Ekleme
                // UsernamePasswordAuthenticationFilter'dan önce ekleyerek
                // brute-force denemelerini henüz kimlik doğrulama başlamadan engelliyoruz.
                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)

                .authorizeHttpRequests(authorize -> authorize
                        // 3. İZİN VERİLENLER:
                        // MFA doğrulama endpoint'ini test edebilmek için erişime açıyoruz.
                        .requestMatchers("/login", "/register", "/css/**", "/js/**", "/mfa-verify").permitAll()

                        // 4. KORUNANLAR: Diğer tüm sayfalar giriş gerektirir.
                        .anyRequest().authenticated()
                )

                // 5. GİRİŞ FORMU YAPILANDIRMASI
                .formLogin(form -> form
                        .loginPage("/login")
                        .successHandler(successHandler)
                        .permitAll()
                )

                // 6. ÇIKIŞ İŞLEMİ YAPILANDIRMASI
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                );

        return http.build();
    }

    /**
     * Şifrelerin güvenli bir şekilde hashlenmesi için BCrypt kullanıyoruz.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}