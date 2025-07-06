package com.geekcatalog.api.service;

import com.geekcatalog.api.dto.userRole.CreateUserRoleLoadDTO;
import com.geekcatalog.api.dto.userRole.UserRoleReturnDTO;

import java.util.List;

public interface UserRoleService {
    List<UserRoleReturnDTO> createUserRoleByLoad(CreateUserRoleLoadDTO data);
    void updateRoles(List<String> rolesId, String userId);
}
