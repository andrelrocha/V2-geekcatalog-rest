package com.geekcatalog.api.dto.role;

import com.geekcatalog.api.domain.role.Role;

public record RoleReturnDTO(String id, String name, String description) {
    public RoleReturnDTO(Role role) {
        this(role.getId(), role.getName(), role.getDescription());
    }
}
