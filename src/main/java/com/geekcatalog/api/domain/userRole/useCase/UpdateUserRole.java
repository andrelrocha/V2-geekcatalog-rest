package com.geekcatalog.api.domain.userRole.useCase;

import com.geekcatalog.api.dto.userRole.CreateUserRoleDTO;
import com.geekcatalog.api.dto.userRole.DeleteUserRoleDTO;
import com.geekcatalog.api.dto.userRole.UserRoleReturnDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class UpdateUserRole {
    @Autowired
    private CreateUserRole createUserRole;
    @Autowired
    private DeleteUserRole deleteUserRole;
    @Autowired
    private GetRolesByUserId getRolesByUserId;

    @Transactional
    public void updateRoles(List<String> rolesId, String userId) {
        Set<String> current = getRolesByUserId.getRolesByUserId(userId)
                .stream()
                .map(ur -> ur.role().id())
                .collect(Collectors.toSet());

        Set<String> toBeDeleted = new HashSet<>(rolesId);

        Set<String> toRemove = new HashSet<>(current);
        toRemove.removeAll(toBeDeleted);

        Set<String> toCreate = new HashSet<>(toBeDeleted);
        toCreate.removeAll(current);

        for (String roleId : toRemove) {
            deleteUserRole.delete(new DeleteUserRoleDTO(userId, roleId));
        }

        for (String roleId : toCreate) {
            createUserRole.create(new CreateUserRoleDTO(userId, roleId));
        }
    }
}
