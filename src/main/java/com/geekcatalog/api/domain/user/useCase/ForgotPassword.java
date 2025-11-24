package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.domain.user.validation.UserValidator;
import com.geekcatalog.api.dto.user.UserOnlyEmailDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;
import com.geekcatalog.api.dto.utils.MailDTO;
import com.geekcatalog.api.infra.exceptions.EmailSendingException;
import com.geekcatalog.api.infra.security.HmacPasswordService;
import com.geekcatalog.api.infra.utils.mail.MailSenderMime;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
public class ForgotPassword {

    @Value("${api.security.hmac.password.secret}")
    private String hmacPasswordSecret;

    private final UserRepository repository;
    private final UserValidator validator;
    private final MailSenderMime mailSender;
    private final HmacPasswordService hmacPasswordService;

    public MessageResponseDTO forgotPassword(UserOnlyEmailDTO data) {
        validator.validateEmailExists(data.email());

        var token = generateForgotPasswordToken(data.email());
        var mailDTO = buildMailDTO(data.email(), token);

        try {
            mailSender.sendMail(mailDTO);
            return new MessageResponseDTO("Successfully sent the email with password reset instructions.");
        } catch (Exception e) {
            throw new EmailSendingException("Error while sending the email with password reset instructions.", e);
        }
    }

    private String generateForgotPasswordToken(String email) {
        var user = repository.findByEmail(email);
        var passwordHash = user.getPassword();

        var timestamp = Instant.now().toString();
        var contentToSign = passwordHash + ":" + timestamp;

        var hmac = hmacPasswordService.generateHmac(contentToSign, hmacPasswordSecret);

        var issuedAt = Instant.now();
        var expiration = issuedAt.plusSeconds(900); // 15 min

        return hmacPasswordService.createToken(
                hmacPasswordSecret,
                email,
                hmac,
                issuedAt,
                expiration
        );
    }

    private MailDTO buildMailDTO(String email, String token) {
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
}
