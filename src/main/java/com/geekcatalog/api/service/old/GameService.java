package com.geekcatalog.api.service.old;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.geekcatalog.api.domain.game.DTO.GameAndIdDTO;
import com.geekcatalog.api.domain.game.DTO.GameDTO;
import com.geekcatalog.api.domain.game.DTO.GameReturnDTO;

public interface GameService {
    Page<GameReturnDTO> getAllGames(Pageable pageable);
    Page<GameReturnDTO> getAllGamesByName(Pageable pageable, String nameCompare);
    GameReturnDTO createGame(GameDTO data);
    GameReturnDTO updateGame(GameDTO data, String gameId);
    Page<GameAndIdDTO> getAllGamesWithID(Pageable pageable);
    void deleteGame(String gameId);
}
