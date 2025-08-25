package com.geekcatalog.api.domain.game.useCase;

import com.geekcatalog.api.domain.game.validator.GameValidator;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

@Component
@RequiredArgsConstructor
public class DeleteGame {
    private final GameRepository repository;
    private final GameValidator validator;
    private final TransactionTemplate transactionTemplate;

    @Transactional
    public void deleteGame(String gameId) {
        validator.validateGameId(gameId);

        var game = repository.findById(gameId)
                .orElseThrow(() -> new ValidationException("Game should exist after ID validation, but no Game was found for the provided ID."));

        transactionTemplate.execute(status -> {
            try {
                // Se precisar deletar entidades relacionadas, inclui aqui

                repository.delete(game);
            } catch (Exception e) {
                status.setRollbackOnly();
                throw new RuntimeException("An error occurred during the delete transaction of a game", e);
            }
            return null;
        });
    }
}
