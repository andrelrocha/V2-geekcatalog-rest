package com.geekcatalog.api.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.geekcatalog.api.domain.game.Game;
import com.geekcatalog.api.domain.game.useCase.CreateGame;
import com.geekcatalog.api.dto.game.GameDTO;
import com.geekcatalog.api.dto.game.GameReturnDTO;
import com.geekcatalog.api.service.GameService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(GamesController.class)
@AutoConfigureMockMvc(addFilters = false)
class GamesControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private GameService gameService;

    @Test
    void shouldReturnCreatedWhenGameIsAdded() throws Exception {
        // Arrange
        GameDTO gameDTO = new GameDTO("The Witcher 3",
                "Open World RPG developed by CD Projekt RED",
                2015);

        Game savedGame = new Game(gameDTO);
        savedGame.setId("fake-id-123");

        GameReturnDTO returnDTO = new GameReturnDTO(savedGame);

        when(gameService.create(any(GameDTO.class))).thenReturn(returnDTO);

        // Act & Assert
        mockMvc.perform(post("/games")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(gameDTO)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.data.id").value("fake-id-123"))
                .andExpect(jsonPath("$.data.name").value("The Witcher 3"))
                .andExpect(jsonPath("$.data.releaseYear").value(2015));

        verify(gameService, times(1)).create(any(GameDTO.class));
    }
}
