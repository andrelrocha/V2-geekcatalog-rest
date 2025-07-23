package com.geekcatalog.api.domain.user.validation;

import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserValidator {
    private final UserRepository repository;

    public void validateSignUp(UserDTO data) {
        if (repository.userExistsByEmail(data.email())) {
            throw new ValidationException("Email on user creation already exists in our database");
        }

        if (repository.userExistsByUsername(data.username())) {
            throw new ValidationException("Username on user creation already exists in our database");
        }
    }

    public void validateUserId(String userId) {
        if (userId == null || userId.trim().isEmpty()) {
            throw new ValidationException("ID must be informed.");
        }

        if (!repository.existsById(userId)) {
            throw new ValidationException("No User was found for the provided ID.");
        }
    }
}
