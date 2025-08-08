package com.geekcatalog.api.domain.gameList.useCase;

import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.security.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.support.MutableSortDefinition;
import org.springframework.beans.support.PagedListHolder;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.gameGenre.GameGenre;
import com.geekcatalog.api.domain.gameGenre.GameGenreRepository;
import com.geekcatalog.api.domain.gameList.GameListRepository;
import com.geekcatalog.api.domain.genres.DTO.GenreCountDTO;

import java.util.*;

@Component
public class GetAllGameListGenresByUser {
    @Autowired
    private GameListRepository gameListRepository;
    @Autowired
    private GameGenreRepository gameGenreRepository;
    @Autowired
    private TokenService tokenService;
    @Autowired
    private UserRepository userRepository;

    public Page<GenreCountDTO> getAllGameListGenresByUserId(String tokenJWT, Pageable pageable) {
        var userId = tokenService.getIdClaim(tokenJWT);
        var user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found during the process of deleting a game comment."));

        var gameListsByUser = gameListRepository.findAllByUserId(user.getId());

        var pageableGenres = PageRequest.of(pageable.getPageNumber(), pageable.getPageSize(), Sort.unsorted());

        var gameGenres = gameListsByUser.stream()
                .flatMap(gameList -> gameGenreRepository.findAllGameGenresByGameId(gameList.getGame().getId(), pageableGenres).stream())
                .toList();

        Map<UUID, GenreCountDTO> genreCountMap = new HashMap<>();
        for (GameGenre gameGenre : gameGenres) {
            var genreId = gameGenre.getGenre().getId();
            var genreName = gameGenre.getGenre().getName();
            genreCountMap.put(genreId, new GenreCountDTO(genreId, genreName, genreCountMap.getOrDefault(genreId, new GenreCountDTO(genreId, genreName, 0)).count() + 1));
        }

        List<GenreCountDTO> genreCountList = new ArrayList<>(genreCountMap.values());

        PagedListHolder<GenreCountDTO> pagedListHolder = new PagedListHolder<>(genreCountList);
        pagedListHolder.setPageSize(pageable.getPageSize());

        MutableSortDefinition sortDefinition = new MutableSortDefinition();
        if (pageable.getSort().isSorted()) {
            pageable.getSort().forEach(order -> {
                sortDefinition.setProperty(order.getProperty());
                sortDefinition.setAscending(order.isAscending());
                sortDefinition.isToggleAscendingOnProperty();
            });
        } else {
            sortDefinition.setProperty("count");
            sortDefinition.setAscending(true);
        }

        pagedListHolder.setSort(sortDefinition);
        pagedListHolder.resort();

        int page = pageable.getPageNumber();
        pagedListHolder.setPage(page);

        int startIndex = pagedListHolder.getPage() * pagedListHolder.getPageSize();
        int endIndex = Math.min(startIndex + pagedListHolder.getPageSize(), genreCountList.size());

        List<GenreCountDTO> currentPageList = genreCountList.subList(startIndex, endIndex);

        return new PageImpl<>(currentPageList, pageable, genreCountList.size());
    }
}