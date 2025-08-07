package com.geekcatalog.api.domain.user.UseCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.dto.user.UserPublicReturnDTO;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

@Component
public class GetPublicInfo {
    @Autowired
    private UserRepository repository;

    public UserPublicReturnDTO getPublicInfoByUserId(String userId) {
        var user = repository.findById(userId)
                .orElseThrow(() -> new ValidationException("No User was found for the provided ID."));

        return new UserPublicReturnDTO(user.getName(), user.getBirthday(), user.getCountry().getNameCommon(), user.getCountry().getId());
    }
}
