package com.geekcatalog.api.domain.user.UseCase;

import com.geekcatalog.api.dto.user.UserReturnDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import com.geekcatalog.api.infra.security.TokenService;

import java.util.UUID;

@Component
public class GetUserByTokenJWT {
    @Autowired
    private UserRepository repository;
    @Autowired
    private TokenService tokenService;

    public UserReturnDTO getUserByIdClaim(String tokenJWT) {
        var userId = tokenService.getIdClaim(tokenJWT);

        var user = repository.findById(userId)
                .orElseThrow(() -> new ValidationException("No user was found for the provided ID."));

        return new UserReturnDTO(user);
    }
}
