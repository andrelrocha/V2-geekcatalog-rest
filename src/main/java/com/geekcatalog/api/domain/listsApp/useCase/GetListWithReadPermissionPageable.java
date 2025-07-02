package com.geekcatalog.api.domain.listsApp.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.listPermissionUser.ListPermissionUser;
import com.geekcatalog.api.domain.listPermissionUser.ListPermissionUserRepository;
import com.geekcatalog.api.domain.listsApp.DTO.ListAppReturnDTO;
import com.geekcatalog.api.domain.listsApp.ListAppRepository;
import com.geekcatalog.api.domain.permission.PermissionEnum;
import com.geekcatalog.api.domain.permission.PermissionRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Component
public class GetListWithReadPermissionPageable {
    @Autowired
    private ListAppRepository listsAppRepository;
    @Autowired
    private PermissionRepository permissionRepository;
    @Autowired
    private ListPermissionUserRepository listPermissionUserRepository;

    public Page<ListAppReturnDTO> getAllListsWithReadPermission(String userId, Pageable pageable) {
        var userIdUUID = UUID.fromString(userId);

        try {
            var readEnum = (PermissionEnum.READ).toString();
            var readPermission = permissionRepository.findByPermissionName(readEnum);
            var listsPermissionWithReadPermissionToUser = listPermissionUserRepository.findAllByParticipantIdAndPermissionId(userIdUUID, readPermission.getId());
            List<UUID> listsAppID = new ArrayList<>();
            for (ListPermissionUser listPermission : listsPermissionWithReadPermissionToUser) {
                listsAppID.add(listPermission.getList().getId());
            }
            var listsWithReadPermissionToUser = listsAppRepository.findAllListsAppById(listsAppID, pageable).map(ListAppReturnDTO::new);
            return listsWithReadPermissionToUser;
        } catch (Exception e) {
            System.err.println("Error while getting lists with read permission: " + e.getMessage());
            throw new RuntimeException(e.getMessage());
        }
    }
}
