package com.geekcatalog.api.domain.gameComment.useCase;

import com.geekcatalog.api.infra.security.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.gameComment.GameCommentRepository;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class DeleteGameComment {
    @Autowired
    private GameCommentRepository gameCommentRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private TokenService tokenService;

    public void deleteGameComment(String tokenJWT, String commentId) {
        var userId = tokenService.getIdClaim(tokenJWT);
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found during the process of deleting a game comment."));

        var commentIdUUID = UUID.fromString(commentId);
        var comment = gameCommentRepository.findById(commentIdUUID)
                .orElseThrow(() -> new ValidationException("Comment with the provided ID was not found."));

        if (!comment.getUser().getId().equals(user.getId())) {
            throw new BadCredentialsException("The user attempting to delete the comment is not its creator.");
        }

        gameCommentRepository.deleteById(comment.getId());
    }
}
