package com.geekcatalog.api.domain.gameGenre.useCase;

import com.geekcatalog.api.domain.gameGenre.DTO.CreateGameGenreDTO;
import com.geekcatalog.api.domain.gameGenre.DTO.GameGenreReturnDTO;
import com.geekcatalog.api.domain.gameGenre.DTO.UpdateGameGenreDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.gameGenre.GameGenre;
import com.geekcatalog.api.domain.gameGenre.GameGenreRepository;
import com.geekcatalog.api.domain.genres.GenreRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.UUID;

@Component
public class UpdateGameGenres {
    @Autowired
    private GameGenreRepository gameGenreRepository;
    @Autowired
    private GameRepository gameRepository;
    @Autowired
    private GenreRepository genreRepository;

    @Autowired
    private GetAllGameGenreByGameID getAllGameGenreByGameID;

    public Page<GameGenreReturnDTO> updateGameGenres(UpdateGameGenreDTO data, String gameId) {
        var gameIdUUID = UUID.fromString(gameId);
        var pageable = PageRequest.of(0, 50);

        var genres = gameGenreRepository.findAllGenreIdsByGameId(gameIdUUID);

        var genresIdDataUUID = new ArrayList<UUID>();
        for (String genreId : data.genres()) {
            var genreIdUUID = UUID.fromString(genreId);
            genresIdDataUUID.add(genreIdUUID);
        }

        var game = gameRepository.findById(gameIdUUID)
                .orElseThrow(() -> new ValidationException("No game ID found during the update of the gamegenre."));

        if (new HashSet<>(genres).containsAll(genresIdDataUUID) && new HashSet<>(genresIdDataUUID).containsAll(genres)) {
            return null;
        } else {
            if (!new HashSet<>(genres).containsAll(genresIdDataUUID)) {
                for (String genreId : data.genres()) {
                    var genreIdUUID = UUID.fromString(genreId);
                    if (genres.contains(genreIdUUID)) {
                        continue;
                    }
                    var genre = genreRepository.findById(genreIdUUID)
                            .orElseThrow(() -> new ValidationException("No genre ID found during the update of the game genre."));

                    var gameGenreDTO = new CreateGameGenreDTO(game, genre);
                    var gameGenre = new GameGenre(gameGenreDTO);
                    gameGenreRepository.save(gameGenre);
                }
            }
            if (genresIdDataUUID.isEmpty()) {
                gameGenreRepository.deleteAllByGameId(gameIdUUID);
            } else if (!new HashSet<>(genresIdDataUUID).containsAll(genres)) {
                gameGenreRepository.deleteGenresByGameIdAndGenreIds(gameIdUUID, genresIdDataUUID);
            }
        }

        return getAllGameGenreByGameID.getAllGameGenresByGameId(gameId, pageable);
    }
}
