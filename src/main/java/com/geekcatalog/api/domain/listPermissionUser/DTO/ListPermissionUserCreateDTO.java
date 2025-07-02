package com.geekcatalog.api.domain.listPermissionUser.DTO;

import com.geekcatalog.api.domain.listsApp.ListApp;
import com.geekcatalog.api.domain.permission.Permission;
import com.geekcatalog.api.domain.user.User;

public record ListPermissionUserCreateDTO(ListApp list, Permission permission, User participant, User owner) {
}
