package com.geekcatalog.api.dto.userRole;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record DeleteUserRoleDTO(@NotNull @NotEmpty String userId, @NotEmpty @NotNull String roleId) {
}
