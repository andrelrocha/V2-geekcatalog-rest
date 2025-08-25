package com.geekcatalog.api.domain.game.useCase;

import com.geekcatalog.api.domain.game.Game;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.game.validator.GameValidator;
import com.geekcatalog.api.dto.game.GameDTO;
import com.geekcatalog.api.dto.game.GameReturnDTO;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class CreateGame {
    private final GameRepository repository;
    private final GameValidator validator;

    @Transactional
    public GameReturnDTO create(GameDTO data) {
        validator.validateNameNotExists(data.name());

        var game = new Game(data);

        var saved = repository.save(game);
        return new GameReturnDTO(saved);
    }
}
