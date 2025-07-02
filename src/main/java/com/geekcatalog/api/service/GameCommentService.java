package com.geekcatalog.api.service;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import com.geekcatalog.api.domain.gameComment.DTO.CreateGameCommentDTO;
import com.geekcatalog.api.domain.gameComment.DTO.GameCommentJOINReturnDTO;
import com.geekcatalog.api.domain.gameComment.DTO.GameCommentReturnDTO;

public interface GameCommentService {
    GameCommentReturnDTO addGameComment(CreateGameCommentDTO data, String tokenJWT);
    Page<GameCommentJOINReturnDTO> getCommentsPageable(Pageable pageable, String gameId);
    void deleteGameComment(String tokenJWT, String commentId);
}
