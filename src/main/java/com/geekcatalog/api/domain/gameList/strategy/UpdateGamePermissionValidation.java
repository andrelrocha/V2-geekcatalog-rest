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
public class UpdateGamePermissionValidation implements PermissionValidationStrategy {
    @Autowired
    private ListPermissionUserRepository listPermissionUserRepository;
    @Autowired
    private GetPermissionByNameENUM getPermissionByNameENUM;

    @Override
    public void validate(UserReturnDTO user, ListApp list) {
        var listsPermission = listPermissionUserRepository.findAllByParticipantIdAndListId(UUID.fromString(user.id()), list.getId());
        if (listsPermission.isEmpty()) {
            throw new ValidationException("The user does not have permission to update games.");
        }

        var permissionEnum = PermissionEnum.UPDATE_GAME;
        var permission = getPermissionByNameENUM.getPermissionByNameOnENUM(permissionEnum);
        var userIdUUID = UUID.fromString(user.id());
        var userPermissionList = listPermissionUserRepository.findByParticipantIdAndListIdAndPermissionId(userIdUUID, list.getId(), permission.id());

        if (userPermissionList == null || !list.getUser().getId().equals(userPermissionList.getOwner().getId())) {
            throw new ValidationException("The user does not have permission to update games.");
        }
    }
}
