package com.geekcatalog.api.domain.utils.fullGame.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.utils.fullGame.DTO.FullGameReturnDTO;
import com.geekcatalog.api.domain.utils.fullGame.DTO.FullGameUpdateDTO;
import com.geekcatalog.api.domain.game.DTO.GameDTO;
import com.geekcatalog.api.domain.game.useCase.UpdateGame;
import com.geekcatalog.api.domain.gameConsole.DTO.UpdateGameConsoleDTO;
import com.geekcatalog.api.domain.gameConsole.useCase.UpdateGameConsoles;
import com.geekcatalog.api.domain.gameGenre.DTO.UpdateGameGenreDTO;
import com.geekcatalog.api.domain.gameGenre.useCase.UpdateGameGenres;
import com.geekcatalog.api.domain.gameStudio.DTO.UpdateGameStudioDTO;
import com.geekcatalog.api.domain.gameStudio.useCase.UpdateGameStudios;

@Service
public class UpdateFullGameAdmin {
    @Autowired
    private UpdateGame updateGameEntity;
    @Autowired
    private UpdateGameGenres updateGameGenres;
    @Autowired
    private UpdateGameStudios updateGameStudios;
    @Autowired
    private UpdateGameConsoles updateGameConsoles;

    @Autowired
    private GetFullGameAdminInfoService getFullGameAdminInfoService;

    public FullGameReturnDTO updateFullGameInfos(FullGameUpdateDTO data, String gameId) {
        try {
            var updateGameDTO = new GameDTO(data.name(), data.metacritic(), data.yearOfRelease());
            updateGameEntity.updateGame(updateGameDTO, gameId);

            if (data.genres() != null) {
                var gameGenresDTO = new UpdateGameGenreDTO(data.genres());
                updateGameGenres.updateGameGenres(gameGenresDTO, gameId);
            }

            if (data.studios() != null) {
                var gameStudiosDTO = new UpdateGameStudioDTO(data.studios());
                updateGameStudios.updateGameStudios(gameStudiosDTO, gameId);
            }

            if (data.consoles() != null) {
                var gameConsolesDTO = new UpdateGameConsoleDTO(data.consoles());
                updateGameConsoles.updateGameConsoles(gameConsolesDTO, gameId);
            }

            return getFullGameAdminInfoService.getFullGameInfoAdmin(gameId);
        } catch(Exception e) {
            throw new RuntimeException("Ocorreu um problema ao tentar editar um jogo no formato próprio do app mobile: " + e.getMessage());
        }
    }
}
