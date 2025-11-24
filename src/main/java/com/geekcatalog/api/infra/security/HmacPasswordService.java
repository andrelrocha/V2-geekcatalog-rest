package com.geekcatalog.api.infra.security;

import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Service
public class HmacPasswordService {

    public String generateHmac(String data, String timestamp, String secret) {
        try {
            String content = data + ":" + timestamp;

            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec key = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
            mac.init(key);

            var hmacBytes = mac.doFinal(content.getBytes());
            return Base64.getEncoder().encodeToString(hmacBytes);

        } catch (Exception e) {
            throw new RuntimeException("Error generating HMAC for password reset.", e);
        }
    }
}
