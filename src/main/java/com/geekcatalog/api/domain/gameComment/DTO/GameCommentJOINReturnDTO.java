package com.geekcatalog.api.domain.gameComment.DTO;

import java.time.LocalDateTime;
import java.util.UUID;

public record GameCommentJOINReturnDTO(
        UUID id,
        UUID userId,
        String username,
        int rating,
        UUID gameId,
        String comment,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {}
