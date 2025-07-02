package com.geekcatalog.api.domain.gameList.DTO;

import com.geekcatalog.api.domain.consoles.DTO.ConsoleReturnDTO;

import java.util.List;
import java.util.UUID;

public record GameListGameAndConsolesDTO(UUID gameId, List<ConsoleReturnDTO> consolesAvailable) {
}
