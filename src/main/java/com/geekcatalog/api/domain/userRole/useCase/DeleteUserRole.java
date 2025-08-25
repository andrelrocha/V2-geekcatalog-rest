package com.geekcatalog.api.domain.userRole.useCase;

import com.geekcatalog.api.domain.userRole.UserRole;
import com.geekcatalog.api.domain.userRole.UserRoleRepository;
import com.geekcatalog.api.dto.userRole.DeleteUserRoleDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import com.geekcatalog.api.service.EntityHandlerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
public class DeleteUserRole {
    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private EntityHandlerService entityHandlerService;

    @Transactional
    public void delete(DeleteUserRoleDTO data) {
        try {
            var user = entityHandlerService.getUserById(data.userId());
            var role = entityHandlerService.getRoleById(data.roleId());

            UserRole userRole = userRoleRepository
                    .findByUserIdAndRoleId(user.getId(), role.getId())
                    .orElseThrow(() -> new ValidationException("The User doesn't have link with the provided Role."));

            // Com orphanRemoval = true, ao remover a entidade da coleção usuarioCargos do usuário,
            // o Hibernate automaticamente identifica que o objeto ficou órfão e gera um DELETE no banco
            // para remover o registro correspondente da tabela usuario_cargo ao executar o flush ou commit.
            user.getUserRoles().remove(userRole);
            userRoleRepository.flush();

        } catch (Exception e) {
            throw new ValidationException(e.getMessage());
        }
    }
}