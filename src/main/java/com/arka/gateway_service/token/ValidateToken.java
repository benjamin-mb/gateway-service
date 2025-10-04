package com.arka.gateway_service.token;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

@Service
public class ValidateToken {
    private final SecretKey secretKey;


    public ValidateToken(@Value("${jwt.secret-key}") SecretKey secretKey) {
        this.secretKey = secretKey;
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

    public boolean isTokenValid(String token,String username){
        final String tokenUsername= extractUserName(token);
        return (tokenUsername.equals(username));
    }
}
