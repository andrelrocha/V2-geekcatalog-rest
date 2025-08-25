package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.domain.user.validation.UserValidator;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import com.geekcatalog.api.infra.security.TokenService;

@Component
@RequiredArgsConstructor
public class GetUserByTokenJWT {
    private final UserRepository repository;
    private final UserValidator validator;
    private final TokenService tokenService;

    public UserReturnDTO getUserByIdClaim(String tokenJWT) {
        var userId = tokenService.getIdClaim(tokenJWT);

        validator.validateUserId(userId);

        var user = repository.findById(userId)
                .orElseThrow(() -> new ValidationException("No user was found for the provided ID, even tough its ID was validated."));

        return new UserReturnDTO(user);
    }
}