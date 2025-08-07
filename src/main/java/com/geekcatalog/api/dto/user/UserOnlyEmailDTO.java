package com.geekcatalog.api.dto.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

public record UserOnlyEmailDTO(
        @NotEmpty
        @Email
        String email) {
}
