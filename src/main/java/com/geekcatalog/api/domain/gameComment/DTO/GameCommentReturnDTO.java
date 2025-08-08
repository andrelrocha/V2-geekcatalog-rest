package com.geekcatalog.api.domain.gameComment.DTO;

import com.geekcatalog.api.domain.gameComment.GameComment;

import java.util.UUID;

public record GameCommentReturnDTO(UUID id, String userId, UUID gameId, String comment) {
    public GameCommentReturnDTO(GameComment gameComment) {
        this(gameComment.getId(), gameComment.getUser().getId(), gameComment.getGame().getId(), gameComment.getComment());
    }
}
