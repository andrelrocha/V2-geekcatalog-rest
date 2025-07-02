package com.geekcatalog.api.domain.imageGame.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.imageGame.DTO.ImageGameReturnDTO;
import com.geekcatalog.api.domain.imageGame.ImageGameRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;


@Component
public class GetImageGameByGameID {
    @Autowired
    private ImageGameRepository repository;

    public ImageGameReturnDTO getImageGamesByGameID(String gameId) {
        var gameIdUUID = UUID.fromString(gameId);
        var imageGame = repository.findImageGameByGameID(gameIdUUID);

        if (imageGame == null) {
            throw new ValidationException("No image was found for the game ID.");
        }
        return new ImageGameReturnDTO(imageGame);
    }
}
