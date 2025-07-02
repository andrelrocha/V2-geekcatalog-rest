package com.geekcatalog.api.domain.gameStudio.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.gameStudio.DTO.CreateGameStudioDTO;
import com.geekcatalog.api.domain.gameStudio.DTO.GameStudioReturnDTO;
import com.geekcatalog.api.domain.gameStudio.DTO.UpdateGameStudioDTO;
import com.geekcatalog.api.domain.gameStudio.GameStudio;
import com.geekcatalog.api.domain.gameStudio.GameStudioRepository;
import com.geekcatalog.api.domain.studios.StudioRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.UUID;

@Component
public class UpdateGameStudios {
    @Autowired
    private GameStudioRepository gameStudioRepository;
    @Autowired
    private GameRepository gameRepository;
    @Autowired
    private StudioRepository studioRepository;

    @Autowired
    private GetAllGameStudioByGameID getAllGameStudioByGameID;

    public Page<GameStudioReturnDTO> updateGameStudios(UpdateGameStudioDTO data, String gameId) {
        var gameIdUUID = UUID.fromString(gameId);
        var pageable = PageRequest.of(0, 50);

        var studios = gameStudioRepository.findAllStudioIdsByGameId(gameIdUUID);

        var studiosIdDataUUID = new ArrayList<UUID>();
        for (String studioId : data.studios()) {
            var consoleIdUUID = UUID.fromString(studioId);
            studiosIdDataUUID.add(consoleIdUUID);
        }

        var game = gameRepository.findById(gameIdUUID)
                .orElseThrow(() -> new ValidationException("Game ID not found during game studio update"));

        if (new HashSet<>(studios).containsAll(studiosIdDataUUID) && new HashSet<>(studiosIdDataUUID).containsAll(studios)) {
            return null;
        } else {
            if (!new HashSet<>(studios).containsAll(studiosIdDataUUID)) {
                for (String studioId : data.studios()) {
                    var studioIdUUID = UUID.fromString(studioId);
                    if (studios.contains(studioIdUUID)) {
                        continue;
                    }
                    var studio = studioRepository.findById(studioIdUUID)
                            .orElseThrow(() -> new ValidationException("Studio ID not found during game studio update"));

                    var gameStudioDTO = new CreateGameStudioDTO(game, studio);
                    var gameStudio = new GameStudio(gameStudioDTO);
                    gameStudioRepository.save(gameStudio);
                }
            }
            if (studiosIdDataUUID.isEmpty()) {
                gameStudioRepository.deleteAllByGameId(gameIdUUID);
            } else if (!new HashSet<>(studiosIdDataUUID).containsAll(studios)) {
                gameStudioRepository.deleteStudiosByGameIdAndStudioIds(gameIdUUID,studiosIdDataUUID);
            }
        }

        return getAllGameStudioByGameID.getAllGameStudiosByGameId(gameId, pageable);
    }
}
