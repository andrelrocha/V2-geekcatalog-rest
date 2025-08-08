package com.geekcatalog.api.dto.userRole;

import com.geekcatalog.api.domain.userRole.UserRole;
import com.geekcatalog.api.dto.role.RoleReturnDTO;
import com.geekcatalog.api.dto.user.UserReturnDTO;

public record UserRoleReturnDTO(RoleReturnDTO role, UserReturnDTO user) {
    public UserRoleReturnDTO(UserRole data) {
        this(new RoleReturnDTO(data.getRole()), new UserReturnDTO(data.getUser()));
    }
}
