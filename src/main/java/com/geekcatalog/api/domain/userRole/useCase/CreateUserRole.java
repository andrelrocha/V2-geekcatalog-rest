package com.geekcatalog.api.domain.userRole.useCase;

import com.geekcatalog.api.domain.userRole.UserRole;
import com.geekcatalog.api.domain.userRole.UserRoleRepository;
import com.geekcatalog.api.dto.userRole.CreateUserRoleDTO;
import com.geekcatalog.api.dto.userRole.UserRoleReturnDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import com.geekcatalog.api.service.EntityHandlerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class CreateUserRole {
    @Autowired
    private UserRoleRepository userRoleRepository;
    @Autowired
    private EntityHandlerService entityHandlerService;

    @Transactional
    public UserRoleReturnDTO create(CreateUserRoleDTO data) {
        try {
            var user = entityHandlerService.getUserById(data.userId());
            var role = entityHandlerService.getRoleById(data.roleId());

            if (!user.isEnabled()) {
                throw new ValidationException("User isn't enabled, therefore it can't be assigned new roles.");
            }

            boolean exists = userRoleRepository.existsByUserIdAndRoleId(user.getId(), role.getId());
            if (exists) {
                throw new ValidationException("The informed Role is already assigned to the provided User.");
            }

            var newUserRole = new UserRole(user, role);
            var savedUserRole = userRoleRepository.save(newUserRole);

            //garante a sincronicidade para que o usuário já fique com o cargo atualizado nessa transação
            user.getUserRoles().add(savedUserRole);

            return new UserRoleReturnDTO(savedUserRole);
        } catch (Exception e) {
            throw new ValidationException(e.getMessage());
        }
    }

}
