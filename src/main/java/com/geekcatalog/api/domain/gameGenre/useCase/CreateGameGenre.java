package com.geekcatalog.api.domain.gameGenre.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.gameGenre.DTO.CreateGameGenreDTO;
import com.geekcatalog.api.domain.gameGenre.DTO.GameGenreDTO;
import com.geekcatalog.api.domain.gameGenre.DTO.GameGenreReturnDTO;
import com.geekcatalog.api.domain.gameGenre.GameGenre;
import com.geekcatalog.api.domain.gameGenre.GameGenreRepository;
import com.geekcatalog.api.domain.genres.GenreRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class CreateGameGenre {
    @Autowired
    private GameGenreRepository repository;

    @Autowired
    private GameRepository gameRepository;

    @Autowired
    private GenreRepository genreRepository;

    public GameGenreReturnDTO createGameGenre(GameGenreDTO data) {
        var gameIdUUID = UUID.fromString(data.gameId());
        var genreIdUUID = UUID.fromString(data.genreId());

        var entityAlreadyCreated = repository.existsByGameIdAndGenreId(gameIdUUID, genreIdUUID);

        if (entityAlreadyCreated) {
            throw new ValidationException("A record with the provided game id and genre id already exists.");
        }

        var game = gameRepository.findById(gameIdUUID)
                .orElseThrow(() -> new ValidationException("No game was found with the provided id when trying to create a gamegenre."));

        var genre = genreRepository.findById(genreIdUUID)
                .orElseThrow(() -> new ValidationException("No genre was found with the provided id when trying to create a gamegenre."));

        var createDTO = new CreateGameGenreDTO(game, genre);

        var gameGenre = new GameGenre(createDTO);

        var gameGenreOnDB = repository.save(gameGenre);

        return new GameGenreReturnDTO(gameGenreOnDB);
    }

}
