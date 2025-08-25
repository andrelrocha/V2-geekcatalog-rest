package com.geekcatalog.api.domain.game;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;

public interface GameRepository extends JpaRepository<Game, String>, JpaSpecificationExecutor<Game> {
    @Query("SELECT CASE WHEN COUNT(g) > 0 THEN true ELSE false END FROM Game g WHERE g.name = :normalizedName")
    boolean existsByNormalizedName(String normalizedName);
}
