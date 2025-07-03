package com.geekcatalog.api.domain.gameRating.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.gameRating.DTO.GameRatingAverageDTO;
import com.geekcatalog.api.domain.gameRating.GameRating;
import com.geekcatalog.api.domain.gameRating.GameRatingRepository;
import com.geekcatalog.api.domain.user.UseCase.GetUserByTokenJWT;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Component
public class GetAverageRatingByUserJWT {
    @Autowired
    private GameRatingRepository gameRatingRepository;
    @Autowired
    private GetUserByTokenJWT getUserByTokenJWT;

    public GameRatingAverageDTO getAverageRatingByJWT(String tokenJWT) {
        var user = getUserByTokenJWT.getUserByID(tokenJWT);

        if (user == null) {
            throw new ValidationException("No user was found for the provided ID.");
        }

        var allRatings = gameRatingRepository.findAllByUserId(user.id());

        int sum = 0;

        for (GameRating rating : allRatings) {
            sum += rating.getRating();
        }

        var gamesRatedQuantity = allRatings.size();

        var averageRating = sum / gamesRatedQuantity;

        return new GameRatingAverageDTO(user.id(), averageRating, gamesRatedQuantity);
    }

}
