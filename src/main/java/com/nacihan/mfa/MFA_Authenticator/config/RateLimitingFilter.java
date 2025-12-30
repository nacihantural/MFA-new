package com.nacihan.mfa.MFA_Authenticator.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;


@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private final Map<String, RequestCounter> requestCounts = new ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_MINUTE = 10;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        String method = request.getMethod();


        if (path.contains("/mfa-verify") && "POST".equalsIgnoreCase(method)) {
            String clientIp = getClientIp(request);

            if (isRateLimited(clientIp)) {
                System.out.println("!!! HIZ LIMITI ASILDI: " + clientIp + " -> " + path);

                response.setStatus(429); // Too Many Requests
                response.setContentType("text/plain; charset=UTF-8");
                response.getWriter().write("Cok fazla deneme yaptiniz. Lutfen 1 dakika bekleyin.");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private boolean isRateLimited(String ip) {
        long currentTime = System.currentTimeMillis();
        RequestCounter counter = requestCounts.computeIfAbsent(ip, k -> new RequestCounter(0, currentTime));

        synchronized (counter) {
            // Eğer 1 dakika geçtiyse sayacı sıfırla
            if (currentTime - counter.startTime > TimeUnit.MINUTES.toMillis(1)) {
                counter.count = 1;
                counter.startTime = currentTime;
                return false;
            }

            counter.count++;
            return counter.count > MAX_REQUESTS_PER_MINUTE;
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

    private static class RequestCounter {
        int count;
        long startTime;

        RequestCounter(int count, long startTime) {
            this.count = count;
            this.startTime = startTime;
        }
    }
}