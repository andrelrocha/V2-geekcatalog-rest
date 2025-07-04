package com.geekcatalog.api.service.impl;

import com.geekcatalog.api.domain.userRole.useCase.CreateUserRoleLoad;
import com.geekcatalog.api.dto.userRole.CreateUserRoleLoadDTO;
import com.geekcatalog.api.dto.userRole.UserRoleReturnDTO;
import com.geekcatalog.api.service.UserRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserRoleServiceImpl implements UserRoleService {
    @Autowired
    private CreateUserRoleLoad createUserRoleLoad;

    @Override
    public List<UserRoleReturnDTO> createUserRoleByLoad(CreateUserRoleLoadDTO data) {
        return createUserRoleLoad.createUserRoleByLoad(data);
    }
}
