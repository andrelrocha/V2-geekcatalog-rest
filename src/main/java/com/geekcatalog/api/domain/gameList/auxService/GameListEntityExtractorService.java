package com.geekcatalog.api.domain.gameList.auxService;

import com.geekcatalog.api.domain.consoles.Console;
import com.geekcatalog.api.domain.game.Game;
import com.geekcatalog.api.domain.gameList.GameList;
import com.geekcatalog.api.domain.listsApp.ListApp;
import com.geekcatalog.api.domain.user.User;

public interface GameListEntityExtractorService {
    User extractUser(String userId);
    ListApp extractList(String listId);
    Game extractGame(String gameId);
    GameList extractGameList(String gameListId);
    Console extractConsole(String consoleId, String gameId);
}
