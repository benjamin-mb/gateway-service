package com.arka.gateway_service.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Service
public class ValidateToken {
    private final SecretKey secretKey;

    public ValidateToken(@Value("${jwt.secret-key}") String secretKeyString) {

        this.secretKey = Keys.hmacShaKeyFor(secretKeyString.getBytes(StandardCharsets.UTF_8));
    }


    public Claims extractAllClaims(String token){
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public String extractUserName(String token){
        return extractAllClaims(token).getSubject();
    }

    public String extractRole(String token){
        Claims claims=extractAllClaims(token);
        return claims.get("auth",String.class);
    }

    public boolean isAdmin(String token) {
        String roles = extractRole(token);
        return roles != null && roles.contains("ROLE_ADMINISTRADOR");
    }

    public boolean isTokenValid(String token,String username){
        final String tokenUsername= extractUserName(token);
        return (tokenUsername.equals(username));
    }
}
