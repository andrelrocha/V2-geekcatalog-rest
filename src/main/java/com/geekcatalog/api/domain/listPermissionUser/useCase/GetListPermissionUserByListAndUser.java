package com.geekcatalog.api.domain.listPermissionUser.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.listPermissionUser.DTO.ListPermissionUserReturnDTO;
import com.geekcatalog.api.domain.listPermissionUser.ListPermissionUserRepository;
import com.geekcatalog.api.domain.listsApp.ListAppRepository;
import com.geekcatalog.api.domain.permission.PermissionRepository;
import com.geekcatalog.api.domain.user.useCase.GetUserByTokenJWT;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class GetListPermissionUserByListAndUser {
    @Autowired
    private ListPermissionUserRepository repository;
    @Autowired
    private ListAppRepository listAppRepository;
    @Autowired
    private GetUserByTokenJWT getUserByTokenJWT;
    @Autowired
    private PermissionRepository permissionRepository;

    public List<ListPermissionUserReturnDTO> getAllPermissionsByUserAndListID(String tokenJWT, String listId) {
        var participant = getUserByTokenJWT.getUserByIdClaim(tokenJWT);
        var participantId = participant.id();
        var listIdUUID = UUID.fromString(listId);
        var list = listAppRepository.findById(listIdUUID)
                .orElseThrow(() -> new ValidationException("No list was found for the provided ID during the permissions search."));

        if (list.getUser().getId().equals(participantId)) {
            var listPermission = new ArrayList<ListPermissionUserReturnDTO>();
            var permissions = permissionRepository.findAllPermissions();
            permissions.forEach(permission -> {
                var dto = new ListPermissionUserReturnDTO(null, listIdUUID, permission.getId(), permission.getPermission(), participantId, participant.name(), participantId);
                listPermission.add(dto);
            });
            return listPermission;
        }

        var allPermissionsByListAndUserID = repository.findAllByParticipantIdAndListId(participantId, listIdUUID)
                .stream()
                .map(ListPermissionUserReturnDTO::new)
                .collect(Collectors.toList());

        return allPermissionsByListAndUserID;
    }

}
