package com.geekcatalog.api.domain.gameList.strategy;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.listPermissionUser.ListPermissionUserRepository;
import com.geekcatalog.api.domain.listsApp.ListApp;
import com.geekcatalog.api.domain.permission.PermissionEnum;
import com.geekcatalog.api.domain.permission.useCase.GetPermissionByNameENUM;
import com.geekcatalog.api.domain.user.DTO.UserReturnDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class AddGamePermissionValidation implements PermissionValidationStrategy {
    @Autowired
    private ListPermissionUserRepository listPermissionUserRepository;
    @Autowired
    private GetPermissionByNameENUM getPermissionByNameENUM;

    @Override
    public void validate(UserReturnDTO user, ListApp list) {
        var userIdUUID = UUID.fromString(user.id());

        if (userIdUUID.equals(list.getUser().getId())) {
            return;
        }

        var listsPermission = listPermissionUserRepository.findAllByParticipantIdAndListId(userIdUUID, list.getId());
        if (listsPermission.isEmpty()) {
            throw new ValidationException("The user does not have permission to add games.");
        }

        var permission = getPermissionByNameENUM.getPermissionByNameOnENUM(PermissionEnum.ADD_GAME);
        var userPermissionList = listPermissionUserRepository.findByParticipantIdAndListIdAndPermissionId(userIdUUID, list.getId(), permission.id());

        if (userPermissionList == null || !list.getUser().getId().equals(userPermissionList.getOwner().getId())) {
            throw new ValidationException("The user does not have permission to add games.");
        }
    }
}
