package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.profilePic.DTO.ProfilePicDTO;
import com.geekcatalog.api.domain.profilePic.DTO.ProfilePicReturnDTO;

import java.io.IOException;
import java.util.UUID;

public interface ProfilePicService {
    ProfilePicReturnDTO addProfilePic(ProfilePicDTO dto) throws IOException;
    byte[] returnProfilePic(UUID userId) throws Exception;
    public void deleteProfilePic(UUID userID);
}
