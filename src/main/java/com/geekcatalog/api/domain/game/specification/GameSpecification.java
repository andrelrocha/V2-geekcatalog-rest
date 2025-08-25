package com.geekcatalog.api.domain.game.specification;

import com.geekcatalog.api.domain.game.Game;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class GameSpecification {

    public static Specification<Game> byFilters(Map<String, Object> filters) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (filters == null) return cb.conjunction();

            if (filters.containsKey("id")) {
                predicates.add(cb.equal(root.get("id"), filters.get("id")));
            }

            if (filters.containsKey("startDate")) {
                Integer startYear = (Integer) filters.get("startDate");
                predicates.add(cb.greaterThanOrEqualTo(root.get("releaseYear"), startYear));
            }

            if (filters.containsKey("endDate")) {
                Integer endYear = (Integer) filters.get("endDate");
                predicates.add(cb.lessThanOrEqualTo(root.get("releaseYear"), endYear));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
