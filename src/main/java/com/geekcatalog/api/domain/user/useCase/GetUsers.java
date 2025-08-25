package com.geekcatalog.api.domain.user.useCase;

import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.domain.user.specification.UserSpecification;
import com.geekcatalog.api.domain.userRole.UserRole;
import com.geekcatalog.api.dto.user.UserReturnDTO;
import com.geekcatalog.api.service.UtilsService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
@RequiredArgsConstructor
public class GetUsers {
    private final UserRepository repository;
    private final UtilsService utilsService;

    public Page<UserReturnDTO> getUsersPageable(
            Pageable pageable,
            String id,
            String email,
            String username,
            String roleId,
            String name
    ) {
        Specification<User> spec = createSpecification(id, email, username, roleId);

        List<User> filteredBySpec = repository.findAll(spec, Sort.unsorted());

        List<User> filteredByName = filterByName(filteredBySpec, name);

        List<User> sorted = sortUsers(filteredByName, pageable);

        return paginate(sorted, pageable);
    }

    private Specification<User> createSpecification(String id, String email, String username, String roleId) {
        Map<String, Object> filters = new HashMap<>();
        if (id != null && !id.isBlank()) filters.put("id", id);
        if (email != null && !email.isBlank()) filters.put("email", email);
        if (username != null && !username.isBlank()) filters.put("username", username);
        if (roleId != null && !roleId.isBlank()) filters.put("roleId", roleId);

        return UserSpecification.byFilters(filters);
    }

    private List<User> filterByName(List<User> users, String name) {
        if (name == null || name.isBlank()) return users;

        String normalized = utilsService.normalizeString(name);
        return users.stream()
                .filter(u -> utilsService.normalizeString(u.getName()).contains(normalized))
                .toList();
    }

    private List<User> sortUsers(List<User> users, Pageable pageable) {
        Map<String, Comparator<User>> comparators = Map.of(
                "id", Comparator.comparing(User::getId, Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)),
                "email", Comparator.comparing(User::getEmail, Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)),
                "username", Comparator.comparing(User::getUsername, Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)),
                "name", Comparator.comparing(u -> utilsService.normalizeString(u.getName()), Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)),
                "phone", Comparator.comparing(User::getPhone, Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)),
                "birthday", Comparator.comparing(User::getBirthday, Comparator.nullsLast(Comparator.naturalOrder())),
                "createdAt", Comparator.comparing(User::getCreatedAt, Comparator.nullsLast(Comparator.naturalOrder())),
                "country", Comparator.comparing(
                        u -> Optional.ofNullable(u.getCountry()).map(c -> utilsService.normalizeString(c.getNameCommon())).orElse(""),
                        Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)
                ),
                "role", Comparator.comparing(
                        u -> u.getUserRoles().stream()
                                .map(UserRole::getRole)
                                .filter(Objects::nonNull)
                                .map(r -> utilsService.normalizeString(r.getName()))
                                .sorted()
                                .findFirst()
                                .orElse(""),
                        Comparator.nullsLast(String.CASE_INSENSITIVE_ORDER)
                )
        );

        String sortField = pageable.getSort().stream()
                .findFirst()
                .map(Sort.Order::getProperty)
                .orElse("username");

        boolean asc = pageable.getSort().stream()
                .findFirst()
                .map(Sort.Order::isAscending)
                .orElse(true);

        Comparator<User> comparator = comparators.getOrDefault(sortField, comparators.get("username"));

        return asc
                ? users.stream().sorted(comparator).toList()
                : users.stream().sorted(comparator.reversed()).toList();
    }

    private Page<UserReturnDTO> paginate(List<User> sortedUsers, Pageable pageable) {
        int total = sortedUsers.size();
        int start = Math.toIntExact(pageable.getOffset());
        int end = Math.min(start + pageable.getPageSize(), total);

        List<UserReturnDTO> pageContent = sortedUsers.subList(start, end).stream()
                .map(UserReturnDTO::new)
                .toList();

        return new PageImpl<>(pageContent, pageable, total);
    }
}