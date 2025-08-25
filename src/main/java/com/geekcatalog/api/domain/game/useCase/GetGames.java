package com.geekcatalog.api.domain.game.useCase;

import com.geekcatalog.api.domain.game.Game;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.game.specification.GameSpecification;
import com.geekcatalog.api.dto.game.GameReturnDTO;
import com.geekcatalog.api.service.UtilsService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
@RequiredArgsConstructor
public class GetGames {

    private final GameRepository repository;
    private final UtilsService utilsService;

    public Page<GameReturnDTO> getGamesPageable(
            Pageable pageable,
            String id,
            String name,
            Integer startYear,
            Integer endYear
    ) {
        Specification<Game> spec = createSpecification(id, startYear, endYear);

        List<Game> filteredBySpec = repository.findAll(spec, Sort.unsorted());

        List<Game> filteredByName = filterByName(filteredBySpec, name);

        List<Game> sorted = sortGames(filteredByName, pageable);

        return paginate(sorted, pageable);
    }

    private Specification<Game> createSpecification(String id, Integer startYear, Integer endYear) {
        Map<String, Object> filters = new HashMap<>();
        if (id != null && !id.isBlank()) filters.put("id", id);
        if (startYear != null) filters.put("startDate", startYear);
        if (endYear != null) filters.put("endDate", endYear);

        return GameSpecification.byFilters(filters);
    }

    private List<Game> filterByName(List<Game> games, String name) {
        if (name == null || name.isBlank()) return games;

        String normalized = utilsService.normalizeString(name);
        return games.stream()
                .filter(g -> utilsService.normalizeString(g.getName()).contains(normalized))
                .toList();
    }

    private List<Game> sortGames(List<Game> games, Pageable pageable) {
        Map<String, Comparator<Game>> comparators = Map.of(
                "id", Comparator.comparing(Game::getId, Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)),
                "name", Comparator.comparing(g -> utilsService.normalizeString(g.getName()), Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)),
                "releaseYear", Comparator.comparing(Game::getReleaseYear, Comparator.nullsLast(Comparator.naturalOrder())),
                "createdAt", Comparator.comparing(Game::getCreatedAt, Comparator.nullsLast(Comparator.naturalOrder()))
        );

        String sortField = pageable.getSort().stream()
                .findFirst()
                .map(Sort.Order::getProperty)
                .orElse("name");

        boolean asc = pageable.getSort().stream()
                .findFirst()
                .map(Sort.Order::isAscending)
                .orElse(true);

        Comparator<Game> comparator = comparators.getOrDefault(sortField, comparators.get("name"));

        return asc
                ? games.stream().sorted(comparator).toList()
                : games.stream().sorted(comparator.reversed()).toList();
    }

    private Page<GameReturnDTO> paginate(List<Game> sortedGames, Pageable pageable) {
        int total = sortedGames.size();
        int start = Math.toIntExact(pageable.getOffset());
        int end = Math.min(start + pageable.getPageSize(), total);

        List<GameReturnDTO> pageContent = sortedGames.subList(start, end).stream()
                .map(GameReturnDTO::new)
                .toList();

        return new PageImpl<>(pageContent, pageable, total);
    }
}
