package com.geekcatalog.api.domain.game;

import com.geekcatalog.api.dto.game.GameDTO;
import com.geekcatalog.api.dto.game.GameUpdateDTO;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Table(name = "game")
@Entity(name = "Game")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class Game {
    @Id
    @Column(name = "id", nullable = false, length = 36, updatable = false)
    private String id;

    @NotNull
    @Column(name = "name", nullable = false, length = 100)
    private String name;

    @Column(name = "description")
    private String description;

    @Column(name = "release_year")
    private Integer releaseYear;

    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    public void onCreate() {
        this.id = UUID.randomUUID().toString().toUpperCase();
        this.createdAt = LocalDateTime.now();
    }

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = LocalDateTime.now();
    }

    public Game(GameDTO data) {
        this.name = data.name();
        this.description = data.description();
        this.releaseYear = data.releaseYear();
    }

    public void updateGame(GameUpdateDTO dto) {
        if (dto.name() != null && !dto.name().isEmpty()) {
            this.name = dto.name();
        }
        if (dto.releaseYear() != null) {
            this.releaseYear = dto.releaseYear();
        }

        if (dto.description() != null && !dto.description().isEmpty()) {
            this.description = dto.description();
        }
    }

}
