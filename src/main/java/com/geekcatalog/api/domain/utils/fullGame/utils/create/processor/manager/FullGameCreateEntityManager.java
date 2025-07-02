package com.geekcatalog.api.domain.utils.fullGame.utils.create.processor.manager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.game.DTO.GameDTO;
import com.geekcatalog.api.domain.game.DTO.GameReturnDTO;
import com.geekcatalog.api.domain.utils.fullGame.DTO.CreateFullGameDTO;
import com.geekcatalog.api.service.GameService;

import static com.geekcatalog.api.infra.utils.stringFormatter.StringFormatter.capitalizeEachWord;
import static com.geekcatalog.api.infra.utils.stringFormatter.StringFormatter.normalizeString;

@Component
public class FullGameCreateEntityManager {
    @Autowired
    private GameService gameService;

    public GameReturnDTO manageCreateGameEntity(CreateFullGameDTO data) {
        var gameDTO = new GameDTO(capitalizeEachWord(normalizeString(data.name())), data.metacritic(), data.yearOfRelease());
        return gameService.createGame(gameDTO);
    }
}
