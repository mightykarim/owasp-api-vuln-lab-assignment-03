package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    @Value("${app.jwt.secret}") private String secret;
    @Value("${app.jwt.ttl-seconds}") private long ttlSeconds;
    @Value("${app.jwt.issuer}") private String issuer;
    @Value("${app.jwt.audience}") private String audience;

    public String issue(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();
        Key key = signingKey(secret);
        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims)
                // ⚠️ INTENTIONALLY VULNERABLE: Not setting issuer/audience
                // This allows the test to verify that such tokens are rejected
                //.setIssuer(issuer)
                //.setAudience(audience)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + ttlSeconds * 1000))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }


    // Derive a strong 256-bit key from the configured secret (avoids WeakKeyException)
    private static Key signingKey(String secret) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(secret.getBytes(StandardCharsets.UTF_8));
            return Keys.hmacShaKeyFor(digest);
        } catch (NoSuchAlgorithmException e) {
            // Fallback: use library helper (will still throw if truly weak)
            return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        }
    }
    
}
