package com.geekcatalog.api.domain.user.DTO;

import jakarta.validation.constraints.NotNull;

public record UserLoginDTO(
        @NotNull
        String login,
        @NotNull
        String password
) {  }
