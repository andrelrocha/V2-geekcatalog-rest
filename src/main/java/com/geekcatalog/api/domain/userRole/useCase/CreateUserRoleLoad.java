package com.geekcatalog.api.domain.userRole.useCase;

import com.geekcatalog.api.domain.userRole.UserRole;
import com.geekcatalog.api.domain.userRole.UserRoleRepository;
import com.geekcatalog.api.dto.userRole.CreateUserRoleLoadDTO;
import com.geekcatalog.api.dto.userRole.UserRoleReturnDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import com.geekcatalog.api.service.EntityHandlerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class CreateUserRoleLoad {
    @Autowired
    private UserRoleRepository repository;
    @Autowired
    private EntityHandlerService entityHandlerService;

    public List<UserRoleReturnDTO> createUserRoleByLoad(CreateUserRoleLoadDTO data) {
        try {
            Set<String> nomesUnicos = new HashSet<>(data.roleNames());
            if (nomesUnicos.size() < data.roleNames().size()) {
                throw new ValidationException("There are duplicate roles in the input list.");
            }

            var user = entityHandlerService.getUserById(data.userId());
            var roles = entityHandlerService.getRolesByNames(data.roleNames());

            if (!user.isEnabled()) {
                throw new ValidationException("The user is inactive and cannot be assigned roles.");
            }

            List<UserRole> newUserRoles = roles.stream()
                    .filter(role -> !repository.existsByUserIdAndRoleId(user.getId(), role.getId()))
                    .map(role -> new UserRole(user, role))
                    .toList();

            if (newUserRoles.isEmpty()) {
                throw new ValidationException("All specified roles are already assigned to the user.");
            }

            List<UserRole> saved = repository.saveAll(newUserRoles);

            return saved.stream().map(UserRoleReturnDTO::new).toList();
        } catch (Exception e) {
            throw new ValidationException(e.getMessage());
        }
    }
}
