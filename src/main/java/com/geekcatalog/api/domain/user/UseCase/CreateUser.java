package com.geekcatalog.api.domain.user.UseCase;

import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.user.UserDTO;
import com.geekcatalog.api.dto.userRole.CreateUserRoleLoadDTO;
import com.geekcatalog.api.service.EntityHandlerService;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import com.geekcatalog.api.service.UserRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class CreateUser {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private EntityHandlerService entityHandlerService;
    @Autowired
    private UserRoleService userRoleService;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserReturnDTO signUp(UserDTO data) {
        boolean userExistsByEmail = userRepository.userExistsByEmail(data.email());
        boolean userExistsByUsername = userRepository.userExistsByUsername(data.username());
        if (userExistsByEmail) {
            throw new ValidationException("Email on user creation already exists in our database");
        } else if(userExistsByUsername) {
            throw new ValidationException("Username on user creation already exists in our database");
        }

        var country = entityHandlerService.getCountryById(data.countryId());

        var newUser = new User(data, country);

        String encodedPassword = bCryptPasswordEncoder.encode(data.password());
        newUser.setPassword(encodedPassword);

        var userOnDb = userRepository.save(newUser);

        if (data.rolesName() != null && !data.rolesName().isEmpty()) {
            var loadDTO = new CreateUserRoleLoadDTO(userOnDb.getId(), data.rolesName());
            var listUserRole = userRoleService.createUserRoleByLoad(loadDTO);

            //apos persistir o usuario, os cargos ainda nao estao carregados em usuario.getUsuarioCargos()
            //(provavelmente por causa do contexto de persistencia e ausencia de fetch automatico).
            //para evitar consultas desnecessarias ao banco e garantir que o dto tenha os dados corretos,
            //utilizo diretamente o retorno da criação da relação que ja traz os cargos vinculados.
            return new UserReturnDTO(userOnDb, listUserRole);
        }

        return new UserReturnDTO(userOnDb);
    }
}
