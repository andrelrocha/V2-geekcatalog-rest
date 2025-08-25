package com.geekcatalog.api.domain.userRole;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface UserRoleRepository extends JpaRepository<UserRole, String> {
    @Query("SELECT ur FROM UserRole ur WHERE ur.user.id = :userId")
    UserRole findByUserId(String userId);

    @Query("""
        SELECT ur FROM UserRole ur 
        JOIN ur.role r
        WHERE ur.user.id = :userId
    """)
    List<UserRole> findByUserIdWithRole(String userId);

    @Query("SELECT ur FROM UserRole ur WHERE ur.role.id = :roleId")
    UserRole findByRoleId(String roleId);

    @Query("""
            SELECT CASE WHEN COUNT(ur) > 0 THEN true ELSE false END
            FROM UserRole ur
            WHERE ur.user.id = :userId AND ur.role.id = :roleId
    """)
    boolean existsByUserIdAndRoleId(String userId, String roleId);


    @Query("""
            SELECT ur FROM UserRole ur
            WHERE ur.user.id = :userId AND ur.role.id = :roleId
    """)
    Optional<UserRole> findByUserIdAndRoleId(String userId, String roleId);
}
