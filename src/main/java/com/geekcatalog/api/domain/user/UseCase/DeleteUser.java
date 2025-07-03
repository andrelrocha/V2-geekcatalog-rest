package com.geekcatalog.api.domain.user.UseCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import com.geekcatalog.api.domain.gameList.GameListRepository;
import com.geekcatalog.api.domain.gameRating.GameRatingRepository;
import com.geekcatalog.api.domain.listPermissionUser.ListPermissionUserRepository;
import com.geekcatalog.api.domain.listsApp.ListAppRepository;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class DeleteUser {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private GetUserByTokenJWT getUserByTokenJWT;
    @Autowired
    private GameListRepository gameListRepository;
    @Autowired
    private GameRatingRepository gameRatingRepository;
    @Autowired
    private ListPermissionUserRepository listPermissionUserRepository;
    @Autowired
    private ListAppRepository listAppRepository;
    @Autowired
    private TransactionTemplate transactionTemplate;

    public void deleteUser(String tokenJWT) {
        var userDTO = getUserByTokenJWT.getUserByID(tokenJWT);
        var user = userRepository.findById(userDTO.id())
                .orElseThrow(() -> new ValidationException("No User was found for the provided ID."));

        transactionTemplate.execute(status -> {
            try {
                var gameListsToDelete = gameListRepository.findAllByUserId(user.getId());
                var gameRatingsToDelete = gameRatingRepository.findAllByUserId(user.getId());
                var listsPermissionUserToDelete = listPermissionUserRepository.findAllByUserId(user.getId());
                var listsAppToDelete = listAppRepository.findAllByUserId(user.getId());


                if (!gameListsToDelete.isEmpty()) {
                    gameListRepository.deleteAll(gameListsToDelete);
                }
                if (!gameListsToDelete.isEmpty()) {
                    gameListRepository.deleteAll(gameListsToDelete);
                }
                if (!gameRatingsToDelete.isEmpty()) {
                    gameRatingRepository.deleteAll(gameRatingsToDelete);
                }
                if (!listsPermissionUserToDelete.isEmpty()) {
                    listPermissionUserRepository.deleteAll(listsPermissionUserToDelete);
                }
                if (!listsAppToDelete.isEmpty()) {
                    listAppRepository.deleteAll(listsAppToDelete);
                }

                userRepository.delete(user);
            } catch (Exception e) {
                status.setRollbackOnly();
                throw new RuntimeException("An error occurred during the delete transaction of the game and its related entities", e);
            }
            return null;
        });
    }
}
