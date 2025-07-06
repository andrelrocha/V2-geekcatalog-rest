package com.geekcatalog.api.domain.user.UseCase;

import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.dto.user.UserUpdateDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.country.Country;
import com.geekcatalog.api.domain.country.CountryRepository;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import com.geekcatalog.api.infra.security.TokenService;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

@Component
public class UpdateUser {
    @Autowired
    private UserRepository repository;
    @Autowired
    private CountryRepository countryRepository;
    @Autowired
    private TokenService tokenService;

    public UserReturnDTO updateUserInfo(UserUpdateDTO dto, String tokenJWT) {
        var userId = tokenService.getIdClaim(tokenJWT);
        userId = userId.replaceAll("\"", "");

        var user = repository.findByIdToHandle(userId);

        if (user == null) {
            throw new ValidationException("No User was found for the provided ID.");
        }

        Country country = null;
        if (dto.countryId() != null) {
            country = countryRepository.findById(dto.countryId())
                    .orElseThrow(() -> new ValidationException("No country was found fot the informed ID, during user update."));
        }

        user.updateUser(dto, country);

        var userUpdated = repository.save(user);

        return new UserReturnDTO(userUpdated);
    }
}
