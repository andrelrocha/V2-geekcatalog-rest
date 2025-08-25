package com.geekcatalog.api.domain.user;

import com.geekcatalog.api.domain.role.Role;
import com.geekcatalog.api.dto.user.*;
import com.geekcatalog.api.domain.userRole.UserRole;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import com.geekcatalog.api.domain.country.Country;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Table(name = "app_user")
@Entity(name = "User")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class User implements UserDetails {

    @Id
    @Column(name = "id", nullable = false, length = 36, updatable = false)
    private String id;

    @Column(name = "email", unique = true, nullable = false, length = 100)
    private String email;

    @Column(name = "username", unique = true, nullable = false, length = 20)
    private String username;

    @Column(name = "password", nullable = false)
    private String password;

    @Column(name = "name", nullable = false, length = 100)
    private String name;

    @Column(name = "phone", length = 14)
    private String phone;

    @Column(name = "birthday")
    private LocalDate birthday;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "country_id", referencedColumnName = "id")
    private Country country;

    @Column(name = "token_expiration")
    private LocalDateTime tokenExpiration;

    @Column(name = "token_mail")
    private String tokenMail;

    @Column(name = "access_failed_count")
    private int accessFailedCount = 0;

    @Column(name = "lockout_enabled")
    private boolean lockoutEnabled = false;

    @Column(name = "lockout_end")
    private LocalDateTime lockoutEnd;

    @Column(name = "two_factor_enabled")
    private boolean twoFactorEnabled = false;

    @Column(name = "refresh_token_enabled")
    private boolean refreshTokenEnabled = false;

    @Enumerated(EnumType.STRING)
    @Column(name = "theme", length = 20)
    private UserTheme theme;

    @Column(name = "profile_pic_url", length = 255)
    private String profilePicUrl;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    //aqui deve mapear o nome da coluna em userRole
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    private List<UserRole> userRoles = new ArrayList<>();

    public User(UserDTO dto, Country country) {
        this.email = dto.email();
        this.password = dto.password();
        this.name = dto.name();
        this.username = dto.username();
        this.phone = dto.phone();
        this.birthday = dto.birthday();
        this.country = country;
        this.twoFactorEnabled = Boolean.TRUE.equals(dto.twoFactorEnabled());
        this.refreshTokenEnabled = Boolean.TRUE.equals(dto.refreshTokenEnabled());
        this.theme = dto.theme() != null ? UserTheme.valueOf(dto.theme()) : null;
    }

    public List<String> getRoles() {
        return userRoles.stream()
                .map(UserRole::getRole)
                .filter(Objects::nonNull)
                .map(Role::getName)
                .distinct()
                .toList();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Set<GrantedAuthority> authorities = getRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()))
                .collect(Collectors.toSet());

        if (authorities.stream().noneMatch(auth -> auth.getAuthority().equals("ROLE_USER"))) {
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !lockoutEnabled;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return !lockoutEnabled;
    }

    public void forgotPassword(UserForgotDTO data) {
        this.tokenMail = data.tokenMail();
        this.tokenExpiration = data.tokenExpiration();
    }

    public void updateUser(UserUpdateDTO data, Country country) {
        if (data.name() != null && !data.name().isEmpty()) {
            this.name = data.name();
        }

        if (data.phone() != null) {
            this.phone = data.phone();
        }

        if (data.birthday() != null) {
            this.birthday = data.birthday();
        }

        if (data.twoFactorEnabled() != null) {
            this.twoFactorEnabled = data.twoFactorEnabled();
        }

        if (data.refreshTokenEnabled() != null) {
            this.refreshTokenEnabled = data.refreshTokenEnabled();
        }

        if (data.theme() != null) {
            this.theme = UserTheme.valueOf(data.theme());
        }

        if (country != null) {
            this.country = country;
        }
    }

    public void resetAccessCount() {
        this.accessFailedCount = 0;
        this.setLockoutEnabled(false);
        this.setLockoutEnd(null);
    }

    @PrePersist
    protected void onCreate() {
        this.id = UUID.randomUUID().toString().toUpperCase();
        createdAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public void updateCountry(Country country) {
        this.country = country;
    }
}
