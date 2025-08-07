package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.userRole.useCase.CreateUserRoleLoad;
import com.geekcatalog.api.domain.userRole.useCase.UpdateUserRole;
import com.geekcatalog.api.dto.userRole.CreateUserRoleLoadDTO;
import com.geekcatalog.api.dto.userRole.UserRoleReturnDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserRoleService {

    private final CreateUserRoleLoad createUserRoleLoad;
    private final UpdateUserRole updateUserRole;

    public List<UserRoleReturnDTO> createUserRoleByLoad(CreateUserRoleLoadDTO data) {
        return createUserRoleLoad.createUserRoleByLoad(data);
    }

    public void updateRoles(List<String> rolesId, String userId) {
        updateUserRole.updateRoles(rolesId, userId);
    }
}
