package com.geekcatalog.api.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.gameGenre.DTO.GameGenreDTO;
import com.geekcatalog.api.domain.gameGenre.DTO.GameGenreReturnDTO;
import com.geekcatalog.api.domain.gameGenre.DTO.UpdateGameGenreDTO;
import com.geekcatalog.api.domain.gameGenre.useCase.CreateGameGenre;
import com.geekcatalog.api.domain.gameGenre.useCase.GetAllGameGenreByGameID;
import com.geekcatalog.api.domain.gameGenre.useCase.UpdateGameGenres;
import com.geekcatalog.api.service.GameGenreService;

@Service
public class GameGenreServiceImpl implements GameGenreService {
    @Autowired
    private GetAllGameGenreByGameID getAllGameGenreByGameID;
    @Autowired
    private CreateGameGenre createGameGenre;
    @Autowired
    private UpdateGameGenres updateGameGenres;

    @Override
    public GameGenreReturnDTO createGameGenre(GameGenreDTO data) {
        var newGameGenre = createGameGenre.createGameGenre(data);
        return newGameGenre;
    }

    @Override
    public Page<GameGenreReturnDTO> getAllGameGenresByGameId(String gameId, Pageable pageable) {
        var gameGenresByGameId = getAllGameGenreByGameID.getAllGameGenresByGameId(gameId, pageable);
        return gameGenresByGameId;
    }

    @Override
    public Page<GameGenreReturnDTO> updateGameGenres(UpdateGameGenreDTO data, String gameId) {
        var gameGenres = updateGameGenres.updateGameGenres(data, gameId);
        return gameGenres;
    }
}
