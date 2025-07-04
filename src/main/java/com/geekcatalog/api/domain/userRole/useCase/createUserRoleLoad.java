package com.geekcatalog.api.domain.userRole.useCase;

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
public class createUserRoleLoad {
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

            List<UsuarioCargo> novosUsuarioCargos = cargos.stream()
                    .filter(cargo -> !usuarioCargoRepository.existsByUsuarioIdAndCargoId(usuario.getId(), cargo.getId()))
                    .map(cargo -> new UsuarioCargo(usuario, cargo))
                    .toList();

            if (novosUsuarioCargos.isEmpty()) {
                throw new ValidationException("Todos os cargos informados já estão atribuídos ao usuário.");
            }

            List<UsuarioCargo> salvos = usuarioCargoRepository.saveAll(novosUsuarioCargos);

            return salvos.stream().map(UsuarioCargoRetornoDTO::new).toList();
        } catch (Exception e) {
            throw new ValidationException(e.getMessage());
        }
    }
}
