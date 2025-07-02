package com.geekcatalog.api.domain.game.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.game.DTO.GameAndIdDTO;
import com.geekcatalog.api.domain.game.GameRepository;

@Component
public class GetAllGamesWithID {
    @Autowired
    private GameRepository repository;

    public Page<GameAndIdDTO> getAllGamesWithID(Pageable pageable) {
        return repository.findAllGames(pageable).map(GameAndIdDTO::new);
    }
}
