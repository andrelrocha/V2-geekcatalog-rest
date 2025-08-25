package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.domain.user.validation.UserValidator;
import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.userRole.CreateUserRoleLoadDTO;
import com.geekcatalog.api.service.EntityHandlerService;
import com.geekcatalog.api.service.UserRoleService;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@AllArgsConstructor
public class CreateUser {
    private final UserRepository repository;
    private final UserValidator validator;
    private final EntityHandlerService entityHandlerService;
    private final UserRoleService userRoleService;

    @Transactional
    public UserReturnDTO create(UserDTO data) {
        validator.validateSignUp(data);

        var country = entityHandlerService.getCountryById(data.countryId());

        var newUser = new User(data, country);

        var savedUser = repository.save(newUser);

        var roles = data.rolesName();
        if (roles != null && !roles.isEmpty()) {
            return assignRolesAndReturn(savedUser, roles);
        }

        return new UserReturnDTO(savedUser);
    }

    private UserReturnDTO assignRolesAndReturn(User user, List<String> roles) {
        var loadDTO = new CreateUserRoleLoadDTO(user.getId(), roles);
        var userRoles = userRoleService.createUserRoleByLoad(loadDTO);

        //apos persistir o usuario, os cargos ainda nao estao carregados em usuario.getUsuarioCargos()
        //(provavelmente por causa do contexto de persistencia e ausencia de fetch automatico).
        //para evitar consultas desnecessarias ao banco e garantir que o dto tenha os dados corretos,
        //utilizo diretamente o retorno da criação da relação que ja traz os cargos vinculados.
        return new UserReturnDTO(user, userRoles);
    }
}
