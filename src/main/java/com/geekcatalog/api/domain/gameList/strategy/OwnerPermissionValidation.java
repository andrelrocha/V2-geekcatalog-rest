package com.geekcatalog.api.domain.gameList.strategy;

import com.geekcatalog.api.dto.user.UserReturnDTO;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.listsApp.ListApp;


@Component
public class OwnerPermissionValidation implements PermissionValidationStrategy {
    @Override
    public void validate(UserReturnDTO user, ListApp list) {
        // ele já é o dono da lista, ele faz o que quiser
    }
}
