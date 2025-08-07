package com.geekcatalog.api.dto.userRole;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;

public record CreateUserRoleLoadDTO(@NotNull @NotEmpty String userId, @NotEmpty List<String> roleNames) {
}
