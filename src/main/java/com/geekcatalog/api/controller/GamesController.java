package com.geekcatalog.api.controller;

import com.geekcatalog.api.dto.game.GameDTO;
import com.geekcatalog.api.dto.game.GameUpdateDTO;
import com.geekcatalog.api.dto.utils.ApiResponseDTO;
import com.geekcatalog.api.dto.game.GameReturnDTO;
import com.geekcatalog.api.service.GameService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/games")
@Tag(name = "Game routes mapped on Controller.")
@RequiredArgsConstructor
public class GamesController {
    private final GameService service;

    @GetMapping
    public ResponseEntity<ApiResponseDTO<Page<GameReturnDTO>>> getGames(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "name") String sortField,
            @RequestParam(defaultValue = "asc") String sortOrder,
            @RequestParam(required = false) String id,
            @RequestParam(required = false) String name,
            @RequestParam(required = false) Integer startYear,
            @RequestParam(required = false) Integer endYear
    ) {
        Pageable pageable = PageRequest.of(
                page,
                size,
                Sort.by(Sort.Direction.fromString(sortOrder), sortField)
        );

        Page<GameReturnDTO> result = service.getGamesPageable(
                pageable,
                id,
                name,
                startYear,
                endYear
        );

        return ResponseEntity.ok(ApiResponseDTO.success(result));
    }

    @PostMapping
    public ResponseEntity<ApiResponseDTO<GameReturnDTO>> create(@RequestBody @Valid GameDTO data) {
        var gameOnDB = service.create(data);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponseDTO.success(gameOnDB));
    }

    @DeleteMapping("/{gameId}")
    public ResponseEntity<Void> delete(@PathVariable String gameId) {
        service.deleteGame(gameId);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{gameId}")
    public ResponseEntity<ApiResponseDTO<GameReturnDTO>> update(@PathVariable String gameId, @RequestBody GameUpdateDTO data) {
        var updatedGame = service.updateGame(gameId, data);
        return ResponseEntity.ok(ApiResponseDTO.success(updatedGame));
    }
}
