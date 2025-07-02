package com.geekcatalog.api.domain.profilePic.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.profilePic.ProfilePicRepository;

import java.util.UUID;

@Component
public class DeleteProfilePic {
    @Autowired
    private ProfilePicRepository repository;

    public void deleteProfilePic(UUID userId) {
        var userHasPhoto = repository.existsByUserId(userId);

        if (!userHasPhoto) {
            throw new RuntimeException("No profile pic was found for the informed User ID.");
        }

        repository.deleteByUserId(userId);
    }
}
