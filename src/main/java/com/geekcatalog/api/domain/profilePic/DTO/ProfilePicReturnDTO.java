package com.geekcatalog.api.domain.profilePic.DTO;

import com.geekcatalog.api.domain.profilePic.ProfilePic;

import java.util.UUID;

public record ProfilePicReturnDTO(UUID id, String login) {
    public ProfilePicReturnDTO(ProfilePic profilePic) {
        this(profilePic.getUser().getId(), profilePic.getUser().getLogin());
    }
}
