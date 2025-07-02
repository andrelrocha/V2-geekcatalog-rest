package com.geekcatalog.api.domain.permission.DTO;

import com.geekcatalog.api.domain.permission.Permission;

import java.util.UUID;

public record PermissionReturnDTO(UUID id, String permission) {
    public PermissionReturnDTO(Permission permission) {
        this(permission.getId(), permission.getPermission());
    }
}