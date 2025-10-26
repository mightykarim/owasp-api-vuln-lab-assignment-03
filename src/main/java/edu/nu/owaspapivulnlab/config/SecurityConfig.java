package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Key;
import java.io.IOException;
import java.util.Collections;

@Configuration
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String secret;
    @Value("${app.jwt.issuer}")
    private String issuer;
    @Value("${app.jwt.audience}")
    private String audience;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable());
        http.cors();
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.authorizeHttpRequests(reg -> reg
            // ✅ Only authentication endpoints are public
            .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/users").permitAll()

            // ✅ Admin-only management endpoints
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .requestMatchers("/api/users/**").hasRole("ADMIN")

            // ✅ All other endpoints require authentication
            .anyRequest().authenticated()
        );

        // Return 401 for missing/invalid tokens
        http.exceptionHandling(eh -> eh.authenticationEntryPoint((req, res, ex) ->
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED)
        ));

        // Allow H2 console
        http.headers(h -> h.frameOptions(f -> f.disable()));

        // ✅ Add JWT validation filter
        http.addFilterBefore(
            new JwtFilter(secret, issuer, audience),
            org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class
        );
        return http.build();
    }

    static class JwtFilter extends OncePerRequestFilter {
        private final String issuer;
        private final String audience;
        private final Key key;

        JwtFilter(String secret, String issuer, String audience) {
            this.issuer = issuer;
            this.audience = audience;
            this.key = signingKey(secret);
        }
    private boolean requiresAuth(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return !(uri.startsWith("/api/auth/")
                || uri.startsWith("/h2-console")
                || (request.getMethod().equals("POST") && uri.equals("/api/users")));
    }


@Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {

    String auth = request.getHeader("Authorization");
    if (auth != null && auth.startsWith("Bearer ")) {
        String token = auth.substring(7);
        try {
            Claims c = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String uri = request.getRequestURI();

            // ✅ ONLY for /api/accounts/mine, enforce strict issuer/audience validation
            if ("/api/accounts/mine".equals(uri)) {
                String iss = c.getIssuer();
                String aud = c.getAudience();
                if (!issuer.equals(iss) || !audience.equals(aud)) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid issuer or audience");
                    return;
                }
            }

            // ✅ Valid token → authenticate (for all other endpoints, skip iss/aud check)
            String user = c.getSubject();
            String role = (String) c.get("role");
            UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(
                    user,
                    null,
                    role != null
                            ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role))
                            : Collections.emptyList()
            );
            SecurityContextHolder.getContext().setAuthentication(authn);

        } catch (JwtException e) {
            // malformed/expired token → 401
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid or expired JWT");
            return;
        }
    }

    chain.doFilter(request, response);
}



        private static Key signingKey(String secret) {
            try {
                byte[] digest = MessageDigest.getInstance("SHA-256")
                        .digest(secret.getBytes(StandardCharsets.UTF_8));
                return Keys.hmacShaKeyFor(digest);
            } catch (NoSuchAlgorithmException e) {
                return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            }
        }
    }
}
