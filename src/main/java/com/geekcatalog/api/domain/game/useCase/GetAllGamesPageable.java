package com.geekcatalog.api.domain.game.useCase;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.game.DTO.GameReturnDTO;
import com.geekcatalog.api.domain.game.GameRepository;

@Component
public class GetAllGamesPageable {
    @Autowired
    private GameRepository repository;

    public Page<GameReturnDTO> getAllGames(Pageable pageable) {
        var games = repository.findAllGames(pageable).map(GameReturnDTO::new);
        return games;
    }
}
