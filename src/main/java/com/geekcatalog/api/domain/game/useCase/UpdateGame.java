package com.geekcatalog.api.domain.game.useCase;

import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.game.validator.GameValidator;
import com.geekcatalog.api.dto.game.GameReturnDTO;
import com.geekcatalog.api.dto.game.GameUpdateDTO;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UpdateGame {
    private final GameRepository repository;
    private final GameValidator validator;

    @Transactional
    public GameReturnDTO updateGame(String gameId, GameUpdateDTO data) {
        validator.validateGameId(gameId);

        // Valida se o novo nome não está em uso por outro jogo (ignorando o próprio jogo)
        validator.validateNameNotExists(data.name(), gameId);

        var game = repository.findById(gameId)
                .orElseThrow(() -> new IllegalStateException("No game was found, even tough its ID was validated."));

        game.updateGame(data);

        var gameUpdated = repository.save(game);

        return new GameReturnDTO(gameUpdated);
    }
}
