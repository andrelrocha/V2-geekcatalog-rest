package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.domain.user.validation.UserValidator;
import com.geekcatalog.api.dto.user.UserOnlyEmailDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;
import com.geekcatalog.api.infra.security.HmacPasswordService;
import com.geekcatalog.api.infra.security.TokenService;
import com.geekcatalog.api.infra.utils.mail.*;
import com.geekcatalog.api.dto.utils.MailDTO;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.infra.exceptions.EmailSendingException;
import com.geekcatalog.api.dto.user.UserForgotDTO;
import com.geekcatalog.api.domain.user.UserRepository;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class ForgotPassword {
    @Value("${api.security.hmac.password.secret}")
    private String hmacPasswordSecret;

    private final UserRepository repository;
    private final UserValidator validator;
    private final MailSenderMime mailSender;
    private final TokenService tokenService;
    private final HmacPasswordService hmacPasswordService;


    public MessageResponseDTO forgotPassword(UserOnlyEmailDTO data) {
        validator.validateEmailExists(data.email());

        var token = generateForgotPasswordToken(data.email());

        var mailDTO = getMailDTO(data.email(), token);

        try {
            mailSender.sendMail(mailDTO);
            return new MessageResponseDTO("Successfully sent the email with password reset instructions.");
        } catch (Exception e) {
            throw new EmailSendingException("Error while sending the email with password reset instructions.", e);
        }

    }

    @NotNull
    private static MailDTO getMailDTO(String email, String token) {
        var subject = "Forgot Password - Geek Catalog";

        var body = """
                Hello %s,

                We received a request to reset the password for your account on GeekCatalog.
        
                To proceed with the password reset, please use the token below in the application:
        
                Reset Token: %s
        
                This token is valid for 15 minutes and should only be used on the official platform.
                For security reasons, do not share this code with anyone. 
                The GeekCatalog team will never ask for this token via email or any other communication method.
        
                If you did not request this password reset, please disregard this email.
        
                Sincerely,  
                The GeekCatalog Team
                """.formatted(email, token);


        return new MailDTO(subject, email, body);
    }

    private String generateForgotPasswordToken(String email) {

        var issuedAt = Instant.now();
        var expiration = issuedAt.plusSeconds(900); // 15 minutos
        var jti = UUID.randomUUID().toString();
        var hmacPassword = generatePasswordHmac(email);

        Map<String, Object> claims = Map.of(
                "scope", "update:current_user:password",
                "hmac", hmacPassword
        );

        return tokenService.generateJwtTokenWithClaims(
                hmacPasswordSecret,
                jti,
                email,
                issuedAt,
                expiration,
                claims
        );
    }

    private String generatePasswordHmac(String email) {
        var userPassword = repository.findByEmail(email).getPassword();
        var timestamp = Instant.now().toString();

        return hmacPasswordService.generateHmac(userPassword, timestamp, hmacPasswordSecret);
    }
}