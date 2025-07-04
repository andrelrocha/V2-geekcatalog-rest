package com.geekcatalog.api.domain.gameComment.useCase;

import com.geekcatalog.api.infra.security.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.gameComment.DTO.CreateGameCommentDTO;
import com.geekcatalog.api.domain.gameComment.DTO.GameCommentDTO;
import com.geekcatalog.api.domain.gameComment.DTO.GameCommentReturnDTO;
import com.geekcatalog.api.domain.gameComment.GameComment;
import com.geekcatalog.api.domain.gameComment.GameCommentRepository;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class AddGameComment {
    @Autowired
    private GameCommentRepository gameCommentRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private GameRepository gameRepository;
    @Autowired
    private TokenService tokenService;

    public GameCommentReturnDTO addGameComment(CreateGameCommentDTO data, String tokenJWT) {
        var id = tokenService.getIdClaim(tokenJWT);
        var user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found during the process of adding a game comment."));

        var userEntity = userRepository.findByIdToHandle(user.getId());

        var commentExists = gameCommentRepository.gameCommentExists(userEntity.getId(), UUID.fromString(data.gameId()), data.comment());

        if (commentExists) {
            throw new ValidationException("The user has already made this same comment on this game.");
        }

        var game = gameRepository.findById(UUID.fromString(data.gameId()))
                .orElseThrow(() -> new RuntimeException("Game with the provided ID was not found."));

        var dto = new GameCommentDTO(userEntity, game, data.comment());

        var gameComment = new GameComment(dto);

        var gameCommentOnDB = gameCommentRepository.save(gameComment);

        return new GameCommentReturnDTO(gameCommentOnDB);
    }

}
