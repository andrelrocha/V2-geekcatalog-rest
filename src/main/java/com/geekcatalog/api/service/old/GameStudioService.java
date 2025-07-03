package com.geekcatalog.api.service.old;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.geekcatalog.api.domain.gameStudio.DTO.GameStudioDTO;
import com.geekcatalog.api.domain.gameStudio.DTO.GameStudioReturnDTO;
import com.geekcatalog.api.domain.gameStudio.DTO.UpdateGameStudioDTO;

public interface GameStudioService {
    Page<GameStudioReturnDTO> getAllGameStudiosByGameId(String gameId, Pageable pageable);
    GameStudioReturnDTO createGameStudio(GameStudioDTO data);
    Page<GameStudioReturnDTO> updateGameStudios(UpdateGameStudioDTO data, String gameId);
}
