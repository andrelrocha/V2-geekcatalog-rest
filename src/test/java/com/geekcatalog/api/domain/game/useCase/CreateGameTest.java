package com.geekcatalog.api.domain.game.useCase;

import com.geekcatalog.api.domain.game.Game;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.game.validator.GameValidator;
import com.geekcatalog.api.dto.game.GameDTO;
import com.geekcatalog.api.dto.game.GameReturnDTO;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class CreateGameTest {

    @Mock
    private GameRepository repository;

    @Mock
    private GameValidator validator;

    @InjectMocks
    private CreateGame createGame;

    @BeforeEach
    void setup() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void shouldCreateGameSuccessfully() {
        // Arrange
        GameDTO dto = new GameDTO("The Witcher 3", "Open World RPG developed by CD Projekt RED", 2015);
        Game savedGame = new Game(dto);
        savedGame.setId("fake-id-123");

        doNothing().when(validator).validateNameNotExists(dto.name());
        when(repository.save(any(Game.class))).thenReturn(savedGame);

        // Act
        GameReturnDTO result = createGame.create(dto);

        // Assert
        assertNotNull(result.id());
        assertEquals("The Witcher 3", result.name());
        assertEquals(2015, result.releaseYear());
        verify(validator, times(1)).validateNameNotExists(dto.name());
        verify(repository, times(1)).save(any(Game.class));
    }
}
