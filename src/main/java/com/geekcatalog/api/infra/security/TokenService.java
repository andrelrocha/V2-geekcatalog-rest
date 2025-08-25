package com.geekcatalog.api.infra.security;

import com.geekcatalog.api.domain.user.User;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

@Service
public class TokenService {

    @Value("${api.security.access.secret}")
    private String accessSecret;

    @Value("${api.security.refresh.secret}")
    private String refreshSecret;

    public String generateAccessToken(User user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(accessSecret);

            return JWT.create()
                    .withIssuer("geekcatalog-api")
                    .withSubject(user.getEmail())
                    .withClaim("id", user.getId())
                    .withClaim("role", user.getRoles().toString())
                    .withIssuedAt(Instant.now())
                    .withExpiresAt(accessTokenExpirationDate())
                    .sign(algorithm);

        } catch (JWTCreationException exception) {
            throw new RuntimeException("Error while generating access JWT token.", exception);
        }
    }

    public String generateRefreshToken(User user) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(refreshSecret);
            var builder = JWT.create()
                    .withIssuer("geekcatalog-api")
                    .withSubject(user.getEmail())
                    .withClaim("refreshId", UUID.randomUUID().toString())
                    .withIssuedAt(Instant.now());

            if (user.isRefreshTokenEnabled()) {
                builder.withExpiresAt(refreshTokenExpirationDate());
            }

            return builder.sign(algorithm);

        } catch (JWTCreationException exception) {
            throw new RuntimeException("Error while generating refresh JWT token.", exception);
        }
    }

    public boolean isAccessTokenValid(String tokenJwt) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(accessSecret);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("geekcatalog-api")
                    .build();
            verifier.verify(tokenJwt);
            return true;
        } catch (JWTVerificationException | IllegalArgumentException exception) {
            return false;
        }
    }

    public boolean isRefreshTokenValid(String refreshToken) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(refreshSecret);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("geekcatalog-api")
                    .build();
            verifier.verify(refreshToken);
            return true;
        } catch (JWTVerificationException | IllegalArgumentException exception) {
            return false;
        }
    }

    public String getSubject(String tokenJwt) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(accessSecret);
            return JWT.require(algorithm)
                    .withIssuer("geekcatalog-api")
                    .build()
                    .verify(tokenJwt)
                    .getSubject();
        } catch (JWTVerificationException exception){
            throw new RuntimeException("Invalid or expired JWT token.");
        }
    }

    public String getIdClaim(String tokenJwt) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(accessSecret);
            DecodedJWT decodedJWT = JWT.require(algorithm)
                    .withIssuer("geekcatalog-api")
                    .build()
                    .verify(tokenJwt);
            return decodedJWT.getClaim("id").asString();
        } catch (JWTVerificationException exception){
            throw new RuntimeException("Invalid or expired JWT token.");
        }
    }

    public DecodedJWT parseClaims(String token) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(refreshSecret);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("geekcatalog-api")
                    .build();
            return verifier.verify(token);
        } catch (JWTVerificationException | IllegalArgumentException e) {
            throw new RuntimeException("Invalid or expired token.", e);
        }
    }

    private Instant accessTokenExpirationDate() {
        return LocalDateTime.now().plusMinutes(15).toInstant(ZoneOffset.of("-03:00"));
    }

    private Instant refreshTokenExpirationDate() {
        //se alterar aqui tem que levar em consideração o expiration date do cookie http em cookieManager
        return LocalDateTime.now().plusDays(15).toInstant(ZoneOffset.of("-03:00"));
    }
}
