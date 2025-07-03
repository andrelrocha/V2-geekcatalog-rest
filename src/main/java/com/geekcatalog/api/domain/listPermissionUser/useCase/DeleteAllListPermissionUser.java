package com.geekcatalog.api.domain.listPermissionUser.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.listPermissionUser.DTO.DeleteListPermissionUserDTO;
import com.geekcatalog.api.domain.listPermissionUser.ListPermissionUserRepository;
import com.geekcatalog.api.domain.user.UseCase.GetUserByTokenJWT;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class DeleteAllListPermissionUser {
    @Autowired
    private ListPermissionUserRepository repository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private GetUserByTokenJWT getUserByTokenJWT;

    public void deleteAllListPermission(DeleteListPermissionUserDTO data) {
        var participantInvited = userRepository.findByEmailToHandle(data.participantEmail());
        if (participantInvited == null) {
            throw new ValidationException("No user was found with the provided login as a participant in the process of adding permissions for a user on a list.");
        }

        var listIdUUID = UUID.fromString(data.listId());

        var user = getUserByTokenJWT.getUserByID(data.tokenJwt());
        var ownerId = user.id();
        var owner = userRepository.findById(ownerId)
                .orElseThrow(() -> new ValidationException("No user was found with the provided ID as the owner in the delete list permission process."));

        var listPermissionUser = repository.findAllByListId(listIdUUID);

        if (listPermissionUser.isEmpty()) {
            throw new ValidationException("No permission records were found for the user on the specified list.");
        } else if (!listPermissionUser.get(0).getOwner().equals(owner)) {
            throw new ValidationException("The user trying to delete a permission is not the owner of the list and does not have permission for the operation.");
        }

        repository.deleteAll(listPermissionUser);
    }
}
