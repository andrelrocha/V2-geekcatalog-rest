package com.geekcatalog.api.domain.gameList.DTO;

import com.geekcatalog.api.domain.consoles.Console;

public record GameListUpdateDTO(Console console, String note) {
}
