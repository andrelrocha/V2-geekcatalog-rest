package com.geekcatalog.api.dto.userRole;

import com.geekcatalog.api.domain.userRole.UserRole;

public record UserRoleReturnDTO(String roleId, String roleName, String userId) {
    public UserRoleReturnDTO(UserRole data) {
        this(data.getRole().getId(), data.getRole().getName(), data.getUser().getId());
    }
}
