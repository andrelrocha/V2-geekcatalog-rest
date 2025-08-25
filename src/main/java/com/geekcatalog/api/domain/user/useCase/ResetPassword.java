package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.domain.user.validation.UserValidator;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.dto.user.UserResetPassDTO;
import com.geekcatalog.api.dto.utils.MessageResponseDTO;

import java.time.LocalDateTime;

@Component
@AllArgsConstructor
public class ResetPassword {
    private final UserRepository repository;
    private final UserValidator validator;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Transactional
    public MessageResponseDTO resetPassword(UserResetPassDTO data) {
        try {
            System.out.println("chamando no use case");
            validator.validateEmailExists(data.email());

            var user = repository.findByEmailToHandle(data.email());
            var tokenMail = user.getTokenMail();

            var tokenExpiration = user.getTokenExpiration();
            var now = LocalDateTime.now();

            var tokenIsValid = tokenMail.equals(data.tokenMail()) && now.isBefore(tokenExpiration);

            if (tokenIsValid) {
                String encodedPassword = bCryptPasswordEncoder.encode(data.password());
                user.setPassword(encodedPassword);
                return new MessageResponseDTO("Success reseting user password.");
            } else {
                throw new ValidationException("Invalid reset token key");
            }
        }
        catch (Exception e) {
            throw new ValidationException("Something has happened during the reset password process: " + e.getMessage());
        }
    }
}