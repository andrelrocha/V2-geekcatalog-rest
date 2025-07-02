package com.geekcatalog.api.domain.profilePic.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.profilePic.ProfilePicRepository;
import com.geekcatalog.api.infra.utils.imageCompress.ImageUtils;

import java.util.UUID;

@Component
public class ReturnProfilePic {
    @Autowired
    private ProfilePicRepository repository;

    public byte[] returnProfilePic(UUID userId) throws Exception {
        var profilePic = repository.findProfilePicByUserId(userId);

        if (profilePic == null) {
            throw new RuntimeException("No profile pic was found for the informed User ID.");
        }

        var compressedImage = profilePic.getImage();
        var decompressedImageData = ImageUtils.decompressImage(compressedImage);

        return decompressedImageData;
    }

}
