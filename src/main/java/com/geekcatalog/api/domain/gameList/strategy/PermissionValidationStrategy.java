package com.geekcatalog.api.domain.gameList.strategy;

import com.geekcatalog.api.domain.listsApp.ListApp;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;

public interface PermissionValidationStrategy {
    void validate(UserReturnDTO user, ListApp list) throws ValidationException;
}
