package com.geekcatalog.api.domain.userRole.useCase;

import com.geekcatalog.api.domain.userRole.UserRoleRepository;
import com.geekcatalog.api.dto.userRole.UserRoleReturnDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class GetRolesByUserId {
    @Autowired
    private UserRoleRepository userRoleRepository;

    public List<UserRoleReturnDTO> getRolesByUserId(String userId) {
        return userRoleRepository.findByUserIdWithRole(userId)
                .stream()
                .map(UserRoleReturnDTO::new)
                .toList();
    }
}
