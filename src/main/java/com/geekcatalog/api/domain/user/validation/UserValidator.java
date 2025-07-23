package com.geekcatalog.api.domain.user.validation;

import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserValidator {
    private final UserRepository userRepository;

    public void validateSignUp(UserDTO data) {
        if (userRepository.userExistsByEmail(data.email())) {
            throw new ValidationException("Email on user creation already exists in our database");
        }

        if (userRepository.userExistsByUsername(data.username())) {
            throw new ValidationException("Username on user creation already exists in our database");
        }
    }
}
