package com.geekcatalog.api.domain.gameList.DTO;

import com.geekcatalog.api.domain.consoles.Console;
import com.geekcatalog.api.domain.game.Game;
import com.geekcatalog.api.domain.listsApp.ListApp;
import com.geekcatalog.api.domain.user.User;

public record GameListCreateDTO(User user, Game game, ListApp listApp, Console consolePlayed, String note) {
}
