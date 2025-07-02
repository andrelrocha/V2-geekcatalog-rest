package com.geekcatalog.api.domain.utils.fullGame.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.utils.fullGame.DTO.FullGameReturnDTO;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.gameConsole.GameConsoleRepository;
import com.geekcatalog.api.domain.gameGenre.GameGenreRepository;
import com.geekcatalog.api.domain.gameStudio.GameStudioRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Service
public class GetFullGameAdminInfoService {
    @Autowired
    private GameRepository gameRepository;
    @Autowired
    private GameStudioRepository gameStudioRepository;
    @Autowired
    private GameGenreRepository gameGenreRepository;
    @Autowired
    private GameConsoleRepository gameConsoleRepository;

    public FullGameReturnDTO getFullGameInfoAdmin(String gameId) {
        var gameIdUUID = UUID.fromString(gameId);

        var game = gameRepository.findById(gameIdUUID)
                .orElseThrow(() -> new ValidationException("Não foi encontrado id de jogo para o id informado no full game service"));

        var consoleInfoList = gameConsoleRepository.findAllConsolesInfoByGameId(game.getId());
        var genreInfoList = gameGenreRepository.findAllGenresInfoByGameId(game.getId());
        var studioInfoList = gameStudioRepository.findAllStudioByGameId(game.getId());

        return new FullGameReturnDTO(game, consoleInfoList, genreInfoList, studioInfoList);
    }
}
