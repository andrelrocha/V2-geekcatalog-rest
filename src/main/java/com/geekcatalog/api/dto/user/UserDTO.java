package com.geekcatalog.api.dto.user;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;

public record UserDTO(

        @NotNull
        @Email(message = "Invalid email address")
        String email,

        @NotNull
        @Size(min = 8, message = "Password must be at least 8 characters long")
        @Pattern(
                regexp = "^(?=.*[A-Z])(?=.*\\d).*$",
                message = "Password must contain at least one uppercase letter and one number"
        )
        String password,

        @NotNull
        String name,

        @Size(max = 20, message = "Username must have at most 20 characters")
        @NotNull
        String username,

        @Pattern(
                regexp = "\\(\\d{2,3}\\)\\d{5}-\\d{4}",
                message = "Phone must follow the pattern (99)99999-9999"
        )
        String phone,

        @JsonFormat(pattern = "yyyy-MM-dd")
        @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
        LocalDate birthday,

        String countryId,

        Boolean twoFactorEnabled,
        Boolean refreshTokenEnabled,

        String theme
) {}