package com.geekcatalog.api.domain.game.validator;

import com.geekcatalog.api.domain.game.Game;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.List;

@RequiredArgsConstructor
@Component
public class GameValidator {

    private final GameRepository repository;

    public void validateGameId(String gameId) {
        if (gameId == null || gameId.isBlank()) {
            throw new ValidationException("Game ID cannot be null or blank");
        }

        boolean exists = repository.existsById(gameId);
        if (!exists) {
            throw new ValidationException("Game with the provided ID does not exist");
        }
    }

    public void validateNameNotExists(String name, String excludingId) {
        if (name == null || name.isBlank()) {
            throw new ValidationException("Game name cannot be null or blank");
        }

        List<Game> allGames = repository.findAll();

        boolean nameExists = allGames.stream()
                .filter(g -> !g.getId().equals(excludingId))
                .anyMatch(g -> g.getName().equalsIgnoreCase(name.trim()));

        if (nameExists) {
            throw new ValidationException("Another game with the same name already exists");
        }
    }

    public void validateNameNotExists(String name) {
        validateNameNotExists(name, null);
    }
}
