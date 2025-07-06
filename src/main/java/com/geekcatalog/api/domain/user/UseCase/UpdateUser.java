package com.geekcatalog.api.domain.user.UseCase;

import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.user.UserUpdateDTO;
import com.geekcatalog.api.service.EntityHandlerService;
import com.geekcatalog.api.service.UserRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.country.Country;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

@Component
public class UpdateUser {
    @Autowired
    private GetUserByTokenJWT getUserByTokenJWT;
    @Autowired
    private UserRepository repository;
    @Autowired
    private EntityHandlerService entityHandlerService;
    @Autowired
    private UserRoleService userRoleService;

    public UserReturnDTO updateUserInfo(UserUpdateDTO dto, String tokenJWT) {
        var userDTO = getUserByTokenJWT.getUserByIdClaim(tokenJWT);

        var user = findUserById(userDTO.id());

        Country country = null;
        if (!(dto.countryId().isEmpty() || dto.countryId().isBlank())) {
            country = entityHandlerService.getCountryById(dto.countryId());
        }

        user.updateUser(dto, country);

        var userUpdated = repository.save(user);

        if (!dto.rolesId().isEmpty()) {
            userRoleService.updateRoles(dto.rolesId(), userUpdated.getId());
        }

        userUpdated = findUserById(userUpdated.getId());

        return new UserReturnDTO(userUpdated);
    }

    private User findUserById(String userId) {
        return repository.findById(userId)
                .orElseThrow(() -> new ValidationException("No User was found for the provided ID."));
    }
}
