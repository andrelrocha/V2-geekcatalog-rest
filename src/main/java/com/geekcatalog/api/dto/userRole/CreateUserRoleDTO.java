package com.geekcatalog.api.dto.userRole;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record CreateUserRoleDTO(@NotNull @NotEmpty String userId, @NotNull @NotEmpty String roleId) {
}
