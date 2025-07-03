package com.geekcatalog.api.domain.listPermissionUser.DTO;

import java.util.ArrayList;

public record ListPermissionBulkAddDTO(String listId, ArrayList<String> permissionsId, String participantEmail, String ownerId) {
}
