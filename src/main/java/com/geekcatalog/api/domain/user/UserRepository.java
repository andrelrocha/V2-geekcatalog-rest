package com.geekcatalog.api.domain.user;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.security.core.userdetails.UserDetails;

public interface UserRepository extends JpaRepository<User, String>, JpaSpecificationExecutor<User> {
    UserDetails findByEmail(String email);
    UserDetails findByUsername(String username);

    @Query("""
            SELECT CASE WHEN COUNT(u) > 0 THEN true
            ELSE false END
            FROM User u WHERE u.email = :email
            """)
    boolean userExistsByEmail(String email);

    @Query("""
            SELECT CASE WHEN COUNT(u) > 0 THEN true
            ELSE false END
            FROM User u WHERE u.username = :username
            """)
    boolean userExistsByUsername(String username);

    @Query("""
            SELECT u FROM User u WHERE u.email = :email
            """)
    User findByEmailToHandle(String email);

    @Query("""
            SELECT u FROM User u WHERE u.username = :username
            """)
    User findByUsernameToHandle(String username);

    @Query("""
            SELECT u FROM User u WHERE u.id = :id
            """)
    User findByIdToHandle(String id);

    boolean existsByEmail(String email);

}
