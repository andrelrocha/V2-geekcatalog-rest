package com.geekcatalog.api.domain.permission.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.permission.DTO.PermissionReturnDTO;
import com.geekcatalog.api.domain.permission.PermissionEnum;
import com.geekcatalog.api.domain.permission.PermissionRepository;

@Component
public class GetPermissionByNameENUM {
    @Autowired
    private PermissionRepository repository;

    public PermissionReturnDTO getPermissionByNameOnENUM(PermissionEnum permission) {
        var permissionString = permission.toString();
        var permissionOnDB = repository.findByPermissionName(permissionString);
        return new PermissionReturnDTO(permissionOnDB);
    }
}
