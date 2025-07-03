package com.geekcatalog.api.dto.user;

import jakarta.validation.constraints.NotNull;

public record UserLoginDTO(
        @NotNull
        String login,
        @NotNull
        String password
) {  }
