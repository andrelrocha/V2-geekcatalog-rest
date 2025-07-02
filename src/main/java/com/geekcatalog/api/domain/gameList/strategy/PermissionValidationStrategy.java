package com.geekcatalog.api.domain.gameList.strategy;

import com.geekcatalog.api.domain.listsApp.ListApp;
import com.geekcatalog.api.domain.user.DTO.UserReturnDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;

public interface PermissionValidationStrategy {
    void validate(UserReturnDTO user, ListApp list) throws ValidationException;
}
