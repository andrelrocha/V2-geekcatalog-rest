package com.geekcatalog.api.domain.imageGame_legacy.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.imageGame_legacy.ImageGameLegacyRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import com.geekcatalog.api.infra.utils.imageCompress.ImageUtils;

import java.util.UUID;

@Component
public class ReturnImageFromGame {

    @Autowired
    private ImageGameLegacyRepository repository;

    public byte[] returnImage(UUID gameId) throws Exception {
        var imageGame = repository.findImageGameByGameId(gameId);

        if (imageGame == null) {
            throw new ValidationException("Não foi encontrada imagem para o jogo informado");
        }

        var compressedImage = imageGame.getImage();
        var decompressedImageData = ImageUtils.decompressImage(compressedImage);

        return decompressedImageData;
    }
}
