package com.geekcatalog.api.service.old;

import com.geekcatalog.api.domain.listPermissionUser.DTO.DeleteListPermissionUserDTO;
import com.geekcatalog.api.domain.listPermissionUser.DTO.ListPermissionBulkAddDTO;
import com.geekcatalog.api.domain.listPermissionUser.DTO.ListPermissionUserDTO;
import com.geekcatalog.api.domain.listPermissionUser.DTO.ListPermissionUserReturnDTO;

import java.util.ArrayList;
import java.util.List;

public interface ListPermissionUserService {
    ListPermissionUserReturnDTO addPermissionToUserOnList(ListPermissionUserDTO data);
    ArrayList<ListPermissionUserReturnDTO> addBulkPermissionToUserOnList(ListPermissionBulkAddDTO data);
    void deleteListPermission(ListPermissionUserDTO data);
    void deleteAllListPermission(DeleteListPermissionUserDTO data);
    List<ListPermissionUserReturnDTO> getAllPermissionsByUserAndListID(String tokenJWT, String listId);
}
