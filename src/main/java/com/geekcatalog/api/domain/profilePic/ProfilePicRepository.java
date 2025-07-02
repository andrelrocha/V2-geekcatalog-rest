package com.geekcatalog.api.domain.profilePic;

import jakarta.transaction.Transactional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.UUID;

public interface ProfilePicRepository extends JpaRepository<ProfilePic, UUID> {
    @Query("""
            SELECT pc FROM ProfilePic pc
            WHERE pc.user.id = :userId
            """)
    ProfilePic findProfilePicByUserId(UUID userId);

    boolean existsByUserId(UUID userId);

    @Transactional
    void deleteByUserId(UUID userId);
}
