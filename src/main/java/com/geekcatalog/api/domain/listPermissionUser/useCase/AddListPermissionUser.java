package com.geekcatalog.api.domain.listPermissionUser.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import com.geekcatalog.api.domain.listPermissionUser.DTO.ListPermissionUserCreateDTO;
import com.geekcatalog.api.domain.listPermissionUser.DTO.ListPermissionUserDTO;
import com.geekcatalog.api.domain.listPermissionUser.DTO.ListPermissionUserReturnDTO;
import com.geekcatalog.api.domain.listPermissionUser.ListPermissionUser;
import com.geekcatalog.api.domain.listPermissionUser.ListPermissionUserRepository;
import com.geekcatalog.api.domain.listsApp.ListApp;
import com.geekcatalog.api.domain.listsApp.ListAppRepository;
import com.geekcatalog.api.domain.permission.PermissionEnum;
import com.geekcatalog.api.domain.permission.PermissionRepository;
import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class AddListPermissionUser {
    @Autowired
    private ListPermissionUserRepository listPermissionUserRepository;
    @Autowired
    private ListAppRepository listAppRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PermissionRepository permissionRepository;
    @Autowired
    private TransactionTemplate transactionTemplate;

    public ListPermissionUserReturnDTO addPermissionToUserOnList(ListPermissionUserDTO data) {
        if (data.participantEmail() == null || data.ownerId() == null || data.listId() == null || data.permissionId() == null) {
            throw new ValidationException("All fields are required in the process of adding permissions for a user on a list.");
        }

        var participantInvited = userRepository.findByEmailToHandle(data.participantEmail());
        if (participantInvited == null) {
            throw new ValidationException("No user was found with the provided login as a participant in the process of adding permissions for a user on a list.");
        }

        var ownerList = userRepository.findById(data.ownerId())
                .orElseThrow(() -> new ValidationException("No user was found with the provided ID as the owner in the process of adding permissions for a user on a list."));

        var listAppIdUUID = UUID.fromString(data.listId());
        var listApp = listAppRepository.findById(listAppIdUUID)
                .orElseThrow(() -> new ValidationException("No list was found with the provided ID in the process of adding permissions for a user on a list."));

        var permissionIdUUID = UUID.fromString(data.permissionId());
        var permission = permissionRepository.findById(permissionIdUUID)
                .orElseThrow(() -> new ValidationException("No permission was found with the provided ID in the process of adding permissions for a user on a list."));

        var permissionAlreadyExists = listPermissionUserRepository.existsByParticipantIdAndListIdAndPermissionId(participantInvited.getId(), listAppIdUUID, permissionIdUUID);

        if (permissionAlreadyExists) {
            throw new ValidationException("There is already a permission for the specified list and user.");
        }

        var createDTO = new ListPermissionUserCreateDTO(listApp, permission, participantInvited, ownerList);

        var listPermissionUser = new ListPermissionUser(createDTO);

        final ListPermissionUser[] listPermissionUserOnDB = new ListPermissionUser[1];
        transactionTemplate.execute(status -> {
            try {
                listPermissionUserOnDB[0] = listPermissionUserRepository.save(listPermissionUser);
                createReadPermissionIfNotExists(participantInvited, listApp, ownerList);
            } catch (Exception e) {
                status.setRollbackOnly();
                throw new RuntimeException("An error occurred during the transaction of adding a permission for a user on a list", e);
            }
            return null;
        });

        return new ListPermissionUserReturnDTO(listPermissionUserOnDB[0]);
    }

    public void createReadPermissionIfNotExists(User participantInvited, ListApp listApp, User owner) {
        var readEnum = (PermissionEnum.READ).toString();
        var permission = permissionRepository.findByPermissionName(readEnum);

        var existsReadPermission = listPermissionUserRepository.existsByParticipantIdAndListIdAndPermissionId(participantInvited.getId(), listApp.getId(), permission.getId());

        if (!existsReadPermission) {
            var createDTO = new ListPermissionUserCreateDTO(listApp, permission, participantInvited, owner);
            var listPermissionUserRead = new ListPermissionUser(createDTO);
            listPermissionUserRepository.save(listPermissionUserRead);
        }
    }
}
