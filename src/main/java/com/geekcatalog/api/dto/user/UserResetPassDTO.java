package com.geekcatalog.api.dto.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;

public record UserResetPassDTO(
        @Email
        @NotNull
        String email,
        @NotNull
        String password,
        @NotNull
        String tokenMail
) {
}