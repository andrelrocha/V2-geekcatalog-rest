package com.geekcatalog.api.domain.listPermissionUser.DTO;

import com.geekcatalog.api.domain.listPermissionUser.ListPermissionUser;

import java.util.UUID;

public record ListPermissionUserReturnDTO(UUID id, UUID listId, UUID permissionId, String permissionName, String participantId, String participantName, String ownerId) {
    public ListPermissionUserReturnDTO(ListPermissionUser listPermissionUser) {
        this(listPermissionUser.getId(), listPermissionUser.getList().getId(), listPermissionUser.getPermission().getId(), listPermissionUser.getPermission().getPermission(),
                listPermissionUser.getParticipant().getId(), listPermissionUser.getParticipant().getName(), listPermissionUser.getOwner().getId());
    }
}
