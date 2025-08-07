package com.geekcatalog.api.dto.user;

import jakarta.validation.constraints.NotEmpty;

public record UserSignInDTO(
        @NotEmpty(message = "You must inform an username or email for sign-in.")
        String login,
        @NotEmpty
        String password
) {  }
