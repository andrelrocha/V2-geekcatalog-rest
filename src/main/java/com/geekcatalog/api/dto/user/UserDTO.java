package com.geekcatalog.api.dto.user;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.*;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;
import java.util.List;

public record UserDTO(
        @NotEmpty
        @Email(message = "Invalid email address")
        String email,

        @NotEmpty
        @Size(min = 8, message = "Password must be at least 8 characters long")
        @Pattern(
                regexp = "^(?=.*[A-Z])(?=.*\\d).*$",
                message = "Password must contain at least one uppercase letter and one number"
        )
        String password,

        @NotEmpty
        String name,

        @NotEmpty
        @Size(max = 20, message = "Username must have at most 20 characters")
        String username,

        @Pattern(
                regexp = "\\(\\d{2,3}\\)\\d{5}-\\d{4}",
                message = "Phone must follow the pattern (99)99999-9999"
        )
        String phone,

        @JsonFormat(pattern = "yyyy-MM-dd")
        @DateTimeFormat(iso = DateTimeFormat.ISO.DATE)
        LocalDate birthday,

        @NotEmpty
        String countryId,

        Boolean twoFactorEnabled,
        Boolean refreshTokenEnabled,

        String theme,

        @NotEmpty(message = "At least one role must be informed.")
        List<@NotBlank(message = "Role list can't be blank.") String> rolesName
) {}
