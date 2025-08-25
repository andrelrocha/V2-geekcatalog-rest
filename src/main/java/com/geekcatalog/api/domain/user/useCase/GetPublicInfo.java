package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.domain.user.validation.UserValidator;
import com.geekcatalog.api.dto.country.CountryReturnDTO;
import com.geekcatalog.api.dto.user.UserPublicReturnDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class GetPublicInfo {
    private final UserRepository repository;
    private final UserValidator validator;

    public UserPublicReturnDTO getPublicInfoByUserId(String userId) {
        validator.validateUserId(userId);

        var user = repository.findById(userId)
                .orElseThrow(() -> new ValidationException("No User was found for the provided ID, even tough its ID was just validated."));

        return new UserPublicReturnDTO(user.getName(), user.getUsername(),
                user.getBirthday(), new CountryReturnDTO(user.getCountry()));
    }
}
