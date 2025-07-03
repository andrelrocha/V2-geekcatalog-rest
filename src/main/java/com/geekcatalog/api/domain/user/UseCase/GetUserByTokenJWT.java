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

    public UserReturnDTO getUserByID(String tokenJWT) {
        var userId = tokenService.getIdClaim(tokenJWT);
        userId = userId.replaceAll("\"", "");

        var user = repository.findById(userId)
                .orElseThrow(() -> new ValidationException("No user was found for the provided ID."));

        return new UserReturnDTO(user);
    }
}
