package com.geekcatalog.api.domain.gameList.useCase;

import com.geekcatalog.api.dto.user.UserReturnDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.gameList.DTO.GameListBulkCreateDTO;
import com.geekcatalog.api.domain.gameList.DTO.GameListBulkReturnDTO;
import com.geekcatalog.api.domain.gameList.DTO.GameListCreateDTO;
import com.geekcatalog.api.domain.gameList.GameList;
import com.geekcatalog.api.domain.gameList.GameListRepository;
import com.geekcatalog.api.domain.gameList.auxService.GameListEntityExtractorServiceImpl;
import com.geekcatalog.api.domain.gameList.strategy.PermissionValidationFactory;
import com.geekcatalog.api.domain.gameList.strategy.PermissionValidationStrategy;
import com.geekcatalog.api.domain.permission.PermissionEnum;

import java.util.ArrayList;

@Component
public class AddBulkGameList {
    @Autowired
    private GameListRepository gameListRepository;

    @Autowired
    private PermissionValidationFactory permissionValidationFactory;
    @Autowired
    private GameListEntityExtractorServiceImpl gameListEntityExtractorServiceImpl;

    public ArrayList<GameListBulkReturnDTO> addBulkGamesToList(GameListBulkCreateDTO data) {
        /*
        var user = gameListEntityExtractorServiceImpl.extractUser(data.userId());

        var list = gameListEntityExtractorServiceImpl.extractList(data.listId());

        var userReturnDTO = new UserReturnDTO(user);
        PermissionValidationStrategy strategy = permissionValidationFactory.getStrategy(userReturnDTO, list, PermissionEnum.ADD_GAME);
        strategy.validate(userReturnDTO, list);

        var gameListCreate = new ArrayList<GameList>();
        for (String gameId : data.gamesId()) {
            var game = gameListEntityExtractorServiceImpl.extractGame(gameId);

            if (gameListRepository.existsByGameIdAndListId(game.getId(), list.getId())) {
                continue;
            }

            var gameListCreateDTO = new GameListCreateDTO(user, game, list, null, null);
            gameListCreate.add(new GameList(gameListCreateDTO));
        }

        var gamesOnDB = gameListRepository.saveAll(gameListCreate);

        var gameListReturnDTOs = new ArrayList<GameListBulkReturnDTO>();
        for (GameList gameList : gamesOnDB) {
            gameListReturnDTOs.add(new GameListBulkReturnDTO(gameList));
        }

        return gameListReturnDTOs;

         */

        return null;
    }
}
