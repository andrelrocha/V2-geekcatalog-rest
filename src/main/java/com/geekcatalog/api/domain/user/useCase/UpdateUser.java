package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.domain.country.Country;
import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.domain.user.validation.UserValidator;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.user.UserUpdateDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import com.geekcatalog.api.service.EntityHandlerService;
import com.geekcatalog.api.service.UserRoleService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class UpdateUser {
    private final UserRepository repository;
    private final EntityHandlerService entityHandlerService;
    private final UserRoleService userRoleService;
    private final UserValidator userValidator;

    @Transactional
    public UserReturnDTO updateUserInfo(UserUpdateDTO dto, String userId) {
        userValidator.validateUpdateUser(dto);

        var user = findUserById(userId);

        Country country = null;
        if (dto.countryId() != null && !dto.countryId().isBlank()) {
            country = entityHandlerService.getCountryById(dto.countryId());
        }

        user.updateUser(dto, country);
        var userUpdated = repository.save(user);

        if (dto.rolesId() != null && !dto.rolesId().isEmpty()) {
            userRoleService.updateRoles(dto.rolesId(), userUpdated.getId());
        }

        userUpdated = findUserById(userUpdated.getId());
        return new UserReturnDTO(userUpdated);
    }

    private User findUserById(String userId) {
        return repository.findById(userId)
                .orElseThrow(() -> new ValidationException("No User was found for the provided ID, even tough its ID was checked beforehand."));
    }
}
