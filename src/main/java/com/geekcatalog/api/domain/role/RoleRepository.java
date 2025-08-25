package com.geekcatalog.api.domain.role;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface RoleRepository extends JpaRepository<Role, String> {
    @Query("SELECT r FROM Role r ORDER BY r.name ASC")
    Page<Role> findAllOrderedByNome(Pageable pageable);

    @Query("SELECT r FROM Role r WHERE LOWER(r.name) = LOWER(:name)")
    Role findByName(String name);

    @Query("SELECT r FROM Role r WHERE LOWER(TRIM(r.name)) IN :names")
    List<Role> findAllByNamesIgnoreCaseAndTrimmed(List<String> names);
}
