package com.geekcatalog.api.domain.game.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.gameConsole.GameConsoleRepository;
import com.geekcatalog.api.domain.gameGenre.GameGenreRepository;
import com.geekcatalog.api.domain.gameList.GameListRepository;
import com.geekcatalog.api.domain.gameRating.GameRatingRepository;
import com.geekcatalog.api.domain.gameStudio.GameStudioRepository;
import com.geekcatalog.api.domain.imageGame.ImageGameRepository;
import com.geekcatalog.api.domain.imageGame.useCase.DeleteImageGame;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class DeleteGame {
    @Autowired
    private GameRepository gameRepository;
    @Autowired
    private GameGenreRepository gameGenreRepository;
    @Autowired
    private GameConsoleRepository gameConsoleRepository;
    @Autowired
    private GameStudioRepository gameStudioRepository;
    @Autowired
    private GameListRepository gameListRepository;
    @Autowired
    private ImageGameRepository imageGameRepository;
    @Autowired
    private GameRatingRepository gameRatingRepository;
    @Autowired
    private DeleteImageGame deleteImageGame;
    @Autowired
    private TransactionTemplate transactionTemplate;

    public void deleteGame(String gameId) {
        var gameIdUUID = UUID.fromString(gameId);
        var game = gameRepository.findById(gameIdUUID)
                .orElseThrow(() -> new ValidationException("No game was found with the provided ID in the game deletion process."));

        transactionTemplate.execute(status -> {
            try {
                var gameListToDelete = gameListRepository.findAllByGameId(game.getId());
                var gameGenresToDelete = gameGenreRepository.findAllByGameId(game.getId());
                var gameConsolesToDelete = gameConsoleRepository.findAllByGameId(game.getId());
                var gameStudiosToDelete = gameStudioRepository.findAllByGameId(game.getId());
                var gameRatingToDelete = gameRatingRepository.findAllByGameId(game.getId());
                var imageGameToDelete = imageGameRepository.findImageGameByGameID(game.getId());

                if (!gameListToDelete.isEmpty()) {
                    gameListRepository.deleteAll(gameListToDelete);
                }
                if (!gameGenresToDelete.isEmpty()) {
                    gameGenreRepository.deleteAll(gameGenresToDelete);
                }
                if (!gameConsolesToDelete.isEmpty()) {
                    gameConsoleRepository.deleteAll(gameConsolesToDelete);
                }
                if (!gameStudiosToDelete.isEmpty()) {
                    gameStudioRepository.deleteAll(gameStudiosToDelete);
                }
                if (!gameRatingToDelete.isEmpty()) {
                    gameRatingRepository.deleteAll(gameRatingToDelete);
                }
                if (imageGameToDelete != null) {
                    deleteImageGame.deleteImageGameByGameId(gameId);
                }

                gameRepository.delete(game);
            } catch (Exception e) {
                status.setRollbackOnly();
                throw new RuntimeException("An error occurred during the transaction to delete the game and its related entities.", e);
            }
            return null;
        });
    }
}
