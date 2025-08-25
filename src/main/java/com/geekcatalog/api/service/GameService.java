package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.game.useCase.CreateGame;
import com.geekcatalog.api.domain.game.useCase.DeleteGame;
import com.geekcatalog.api.domain.game.useCase.GetGames;
import com.geekcatalog.api.domain.game.useCase.UpdateGame;
import com.geekcatalog.api.dto.game.GameDTO;
import com.geekcatalog.api.dto.game.GameReturnDTO;
import com.geekcatalog.api.dto.game.GameUpdateDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class GameService {
    private final CreateGame createGame;
    private final DeleteGame deleteGame;
    private final GetGames getGames;
    private final UpdateGame updateGame;

    public Page<GameReturnDTO> getGamesPageable(
            Pageable pageable,
            String id,
            String name,
            Integer startYear,
            Integer endYear
    ) {
        return getGames.getGamesPageable(pageable, id, name, startYear, endYear);
    }

    public GameReturnDTO create(GameDTO data) {
        return createGame.create(data);
    }

    public void deleteGame(String gameId) {
        deleteGame.deleteGame(gameId);
    }

    public GameReturnDTO updateGame(String gameId, GameUpdateDTO data) {
        return updateGame.updateGame(gameId, data);
    }
}
