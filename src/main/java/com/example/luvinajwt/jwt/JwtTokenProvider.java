package com.example.luvinajwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

@Service
@Slf4j
public class JwtTokenProvider {

    /**
     * 24 * 60 * 60 * 1000
     */
    private final Long JWT_EXPIRATION = 86400000L;

    /**
     * 24 * 60 * 60 * 1000 * 7
     */
    private final Long REFRESH_JWT_EXPIRATION = 604800000L;

    @Value("${privateKey}")
    private String privateKeyBase64;

    @Value("${publicKey}")
    private String publicKeyBase64;

    private PrivateKey privateKey;

    private PublicKey publicKey;

    @PostConstruct
    public void init() throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.privateKey = generatePrivateKey(privateKeyBase64);
        this.publicKey = generatePublicKey(publicKeyBase64);
    }

    public PublicKey generatePublicKey(String jwtPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] keyBytes = Base64.decodeBase64(jwtPublicKey);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

    public PrivateKey generatePrivateKey(String jwtPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] keyBytes = Base64.decodeBase64(jwtPrivateKey);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    public String generateToken(UserDetails userDetails) {
        Date current = new Date();
        Date expDate = new Date(current.getTime() + JWT_EXPIRATION);
        return Jwts.builder()
                .setIssuedAt(current)
                .setExpiration(expDate)
                .setSubject(userDetails.getUsername())
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }

    public String generateRefreshToken(UserDetails userDetails) {
        Date current = new Date();
        Date expDate = new Date(current.getTime() + REFRESH_JWT_EXPIRATION);
        return Jwts.builder()
                .setIssuedAt(current)
                .setExpiration(expDate)
                .setSubject(userDetails.getUsername())
                .signWith(SignatureAlgorithm.RS256, privateKey)
                .compact();
    }

    public String getUserNameFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(publicKey)
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);
            return true;
        } catch (MalformedJwtException ex) {
            log.error("Token Invalid");
        } catch (ExpiredJwtException ex) {
            log.error("Token Expired");
        } catch (UnsupportedJwtException ex) {
            log.error("Token Unsupported");
        } catch (IllegalArgumentException ex) {
            log.error("Token Empty");
        }
        return false;
    }
}
