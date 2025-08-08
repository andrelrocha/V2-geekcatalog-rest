package com.geekcatalog.api.domain.user.specification;

import com.geekcatalog.api.domain.user.User;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class UserSpecification {

    public static Specification<User> byFilters(Map<String, Object> filters) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();

            if (filters == null) return cb.conjunction();

            if (filters.containsKey("id")) {
                predicates.add(cb.equal(root.get("id"), filters.get("id")));
            }

            if (filters.containsKey("email")) {
                String email = ((String) filters.get("email")).trim().toLowerCase();
                predicates.add(cb.like(cb.lower(root.get("email")), "%" + email + "%"));
            }

            if (filters.containsKey("username")) {
                String username = ((String) filters.get("username")).trim().toLowerCase();
                predicates.add(cb.like(cb.lower(root.get("username")), "%" + username + "%"));
            }

            if (filters.containsKey("roleId")) {
                Join<Object, Object> join = root.join("userRoles");
                predicates.add(cb.equal(join.get("role").get("id"), filters.get("roleId")));
            }

            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
