package com.geekcatalog.api.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.geekcatalog.api.domain.gameGenre.DTO.GameGenreDTO;
import com.geekcatalog.api.domain.gameGenre.DTO.GameGenreReturnDTO;
import com.geekcatalog.api.domain.gameGenre.DTO.UpdateGameGenreDTO;

public interface GameGenreService {
    GameGenreReturnDTO createGameGenre(GameGenreDTO data);
    Page<GameGenreReturnDTO> getAllGameGenresByGameId(String gameId, Pageable pageable);
    Page<GameGenreReturnDTO> updateGameGenres(UpdateGameGenreDTO data, String gameId);
}
