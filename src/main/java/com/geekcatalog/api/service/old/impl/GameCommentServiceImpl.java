package com.geekcatalog.api.service.old.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.gameComment.DTO.CreateGameCommentDTO;
import com.geekcatalog.api.domain.gameComment.DTO.GameCommentJOINReturnDTO;
import com.geekcatalog.api.domain.gameComment.DTO.GameCommentReturnDTO;
import com.geekcatalog.api.domain.gameComment.useCase.AddGameComment;
import com.geekcatalog.api.domain.gameComment.useCase.DeleteGameComment;
import com.geekcatalog.api.domain.gameComment.useCase.GetGameComments;
import com.geekcatalog.api.service.old.GameCommentService;

@Service
public class GameCommentServiceImpl implements GameCommentService {
    @Autowired
    private AddGameComment addGameComment;
    @Autowired
    private DeleteGameComment deleteGameComment;
    @Autowired
    private GetGameComments getGameComments;

    @Override
    public GameCommentReturnDTO addGameComment(CreateGameCommentDTO data, String tokenJWT) {
        return addGameComment.addGameComment(data, tokenJWT);
    }

    @Override
    public Page<GameCommentJOINReturnDTO> getCommentsPageable(Pageable pageable, String gameId) {
        return getGameComments.getCommentsPageable(pageable, gameId);
    }

    @Override
    public void deleteGameComment(String tokenJWT, String commentId) {
        deleteGameComment.deleteGameComment(tokenJWT, commentId);
    }
}
