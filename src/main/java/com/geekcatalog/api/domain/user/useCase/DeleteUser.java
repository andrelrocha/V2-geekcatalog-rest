package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.domain.user.validation.UserValidator;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

@Component
@RequiredArgsConstructor
public class DeleteUser {
    private final UserRepository repository;
    private final UserValidator validator;
    private final TransactionTemplate transactionTemplate;

    /*@Autowired
    private GameListRepository gameListRepository;
    @Autowired
    private GameRatingRepository gameRatingRepository;
    @Autowired
    private ListPermissionUserRepository listPermissionUserRepository;
    @Autowired
    private ListAppRepository listAppRepository; */

    @Transactional
    public void deleteUser(String userId) {
        validator.validateUserId(userId);

        var user = repository.findById(userId)
                .orElseThrow(() -> new ValidationException("User should exist after ID validation, but no User was found for the provided ID."));

        transactionTemplate.execute(status -> {
            try {
                /*
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
                }*/

                repository.delete(user);
            } catch (Exception e) {
                status.setRollbackOnly();
                throw new RuntimeException("An error occurred during the delete transaction of an user", e);
            }
            return null;
        });
    }
}
