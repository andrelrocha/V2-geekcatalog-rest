package com.geekcatalog.api.dto.user;

import jakarta.validation.constraints.NotEmpty;

public record UserLoginDTO(
        @NotEmpty
        String login,
        @NotEmpty
        String password
) {  }
