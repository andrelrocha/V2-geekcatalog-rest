package com.geekcatalog.api.infra.security;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class HmacPasswordService {

    private final TokenService tokenService;

    public String createToken(
            String secret,
            String subject,
            String hmac,
            Instant issuedAt,
            Instant expiration
    ) {
        var jti = UUID.randomUUID().toString();

        Map<String, Object> claims = Map.of(
                "scope", "update:current_user:password",
                "hmac", hmac
        );

        return tokenService.generateJwtTokenWithClaims(
                secret,
                jti,
                subject,
                issuedAt,
                expiration,
                claims
        );
    }

    public String generateHmac(String contentToSign, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
            mac.init(key);

            var hmacBytes = mac.doFinal(contentToSign.getBytes());
            return Base64.getEncoder().encodeToString(hmacBytes);

        } catch (Exception e) {
            throw new RuntimeException("Error generating HMAC.", e);
        }
    }
}
