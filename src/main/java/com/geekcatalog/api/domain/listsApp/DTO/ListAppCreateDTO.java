package com.geekcatalog.api.domain.listsApp.DTO;

import com.geekcatalog.api.domain.user.User;

public record ListAppCreateDTO(String name, String description, boolean visibility, User user) {
}
