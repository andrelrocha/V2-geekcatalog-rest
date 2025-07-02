package com.geekcatalog.api.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.profilePic.DTO.ProfilePicDTO;
import com.geekcatalog.api.domain.profilePic.DTO.ProfilePicReturnDTO;
import com.geekcatalog.api.domain.profilePic.useCase.AddProfilePic;
import com.geekcatalog.api.domain.profilePic.useCase.DeleteProfilePic;
import com.geekcatalog.api.domain.profilePic.useCase.ReturnProfilePic;
import com.geekcatalog.api.service.ProfilePicService;

import java.io.IOException;
import java.util.UUID;

@Service
public class ProfilePicServiceImpl implements ProfilePicService {
    @Autowired
    private AddProfilePic addProfilePic;
    @Autowired
    private DeleteProfilePic deleteProfilePic;
    @Autowired
    private ReturnProfilePic returnProfilePic;

    @Override
    public ProfilePicReturnDTO addProfilePic(ProfilePicDTO dto) throws IOException {
        var profilePic = addProfilePic.addProfilePic(dto);
        return profilePic;
    }

    @Override
    public byte[] returnProfilePic(UUID userId) throws Exception {
        var profilePic = returnProfilePic.returnProfilePic(userId);
        return profilePic;
    }

    @Override
    public void deleteProfilePic(UUID userId) {
        deleteProfilePic.deleteProfilePic(userId);
    }
}
