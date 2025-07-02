package com.geekcatalog.api.domain.utils.fullGame.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.utils.fullGame.DTO.FullGameUserDTO;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.gameConsole.GameConsoleRepository;
import com.geekcatalog.api.domain.gameGenre.GameGenreRepository;
import com.geekcatalog.api.domain.gameRating.useCase.GetRatingByGameId;
import com.geekcatalog.api.domain.gameStudio.GameStudioRepository;
import com.geekcatalog.api.domain.imageGame.useCase.GetImageGameByGameID;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Service
public class GetFullGameInfoService {
    @Autowired
    private GameRepository gameRepository;
    @Autowired
    private GameStudioRepository gameStudioRepository;
    @Autowired
    private GameGenreRepository gameGenreRepository;
    @Autowired
    private GameConsoleRepository gameConsoleRepository;
    @Autowired
    private GetImageGameByGameID getImageGameByGameID;
    @Autowired
    private GetRatingByGameId getRatingByGameId;

    public FullGameUserDTO getFullGameInfo(String gameId) {
        var gameIdUUID = UUID.fromString(gameId);

        var game = gameRepository.findById(gameIdUUID)
                .orElseThrow(() -> new ValidationException("Não foi encontrado id de jogo para o id informado no full game service"));

        var gameStudio = gameStudioRepository.findAllStudioNamesByGameId(game.getId());

        var gameGenre = gameGenreRepository.findAllGenresNamesByGameId(game.getId());

        var gameConsole = gameConsoleRepository.findAllConsolesNamesByGameId(game.getId());

        var gameImageUrl = getImageGameByGameID.getImageGamesByGameID(gameId).imageUrl();

        var gameRating = getRatingByGameId.getAllRatingsByGameID(gameId);

        return new FullGameUserDTO(game, gameStudio, gameGenre, gameConsole, gameImageUrl, gameRating.totalReviews(), gameRating.averageRating());
    }
}