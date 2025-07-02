package com.geekcatalog.api.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import com.geekcatalog.api.domain.imageGame.DTO.ImageGameReturnDTO;
import com.geekcatalog.api.domain.imageGame.useCase.AddImageGame;
import com.geekcatalog.api.domain.imageGame.useCase.GetImageGameByGameID;
import com.geekcatalog.api.domain.imageGame.useCase.GetImageGamePageable;
import com.geekcatalog.api.service.ImageGameService;

import java.io.IOException;
import java.util.UUID;

@Service
public class ImageGameServiceImpl implements ImageGameService  {
    @Autowired
    private AddImageGame addImageGame;
    @Autowired
    private GetImageGamePageable getImageGamePageable;
    @Autowired
    private GetImageGameByGameID getImageGameByGameID;

    @Override
    public ImageGameReturnDTO addImageGame(MultipartFile file, UUID gameId) throws IOException {
        var imageGameReturn = addImageGame.addImageGame(file, gameId);
        return imageGameReturn;
    }

    @Override
    public Page<ImageGameReturnDTO> getImageGames(Pageable pageable) {
        var imageGames = getImageGamePageable.getImageGames(pageable);
        return imageGames;
    }

    @Override
    public ImageGameReturnDTO getImageGamesByGameID(String gameId) {
        var imageGame = getImageGameByGameID.getImageGamesByGameID(gameId);
        return imageGame;
    }
}
