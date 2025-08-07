package com.geekcatalog.api.domain.user.validation;

import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.domain.user.UserTheme;
import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.user.UserUpdateDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.EnumUtils;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.Period;

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

        validateMinimumAge(data.birthday(), 12);
        validatePhone(data.phone());
    }

    public void validateCredentialsInformed(String login, String password) {
        if (login == null || login.trim().isEmpty()) {
            throw new ValidationException("Login field can't be empty.");
        }
        if (password == null || password.trim().isEmpty()) {
            throw new ValidationException("Password field can't be empty.");
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

    public void validateEmailExists(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new ValidationException("Email must be informed.");
        }

        if (!repository.existsByEmail(email)) {
            throw new ValidationException("No user was found for the provided email.");
        }
    }

    public void validateUpdateUser(UserUpdateDTO dto) {
        if (dto.username() != null && !dto.username().trim().isEmpty()) {
            if (repository.userExistsByUsername(dto.username())) {
                throw new ValidationException("Username is already taken.");
            }
        }

        if (dto.birthday() != null) {
            if (dto.birthday().isAfter(LocalDate.now())) {
                throw new ValidationException("Birthday cannot be a future date.");
            }
            validateMinimumAge(dto.birthday(), 12);
        }

        validatePhone(dto.phone());

        if (dto.theme() != null && !EnumUtils.isValidEnum(UserTheme.class, dto.theme())) {
            throw new ValidationException("Invalid theme provided.");
        }
    }

    public void validateUserExistsAndIsActive(User user) {
        if (user == null) {
            throw new ValidationException("User not found.");
        }

        if (!user.isEnabled()) {
            throw new ValidationException("User is inactive.");
        }
    }

    private void validateMinimumAge(LocalDate birthday, int minimumAge) {
        if (birthday == null || birthday.toString().trim().isEmpty()) return;

        int age = Period.between(birthday, LocalDate.now()).getYears();
        if (age < minimumAge) {
            throw new ValidationException("User must be at least " + minimumAge + " years old.");
        }
    }

    private void validatePhone(String phone) {
        if (phone == null || phone.trim().isEmpty()) return;

        String digitsOnly = phone.replaceAll("\\D", "");
        if (digitsOnly.length() < 8) {
            throw new ValidationException("Phone number must have at least 8 digits.");
        }
    }
}
