package com.geekcatalog.api.domain.gameList.auxService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.consoles.Console;
import com.geekcatalog.api.domain.consoles.ConsoleRepository;
import com.geekcatalog.api.domain.consoles.DTO.ConsoleReturnDTO;
import com.geekcatalog.api.domain.consoles.useCase.GetAllConsolesByGameId;
import com.geekcatalog.api.domain.game.Game;
import com.geekcatalog.api.domain.game.GameRepository;
import com.geekcatalog.api.domain.gameList.GameList;
import com.geekcatalog.api.domain.gameList.GameListRepository;
import com.geekcatalog.api.domain.listsApp.ListApp;
import com.geekcatalog.api.domain.listsApp.ListAppRepository;
import com.geekcatalog.api.domain.user.User;
import com.geekcatalog.api.domain.user.UserRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.UUID;

@Service
public class GameListEntityExtractorServiceImpl implements GameListEntityExtractorService {

    @Autowired
    private GameRepository gameRepository;
    @Autowired
    private ListAppRepository listAppRepository;
    @Autowired
    private ConsoleRepository consoleRepository;
    @Autowired
    private GameListRepository gameListRepository;
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private GetAllConsolesByGameId getAllConsolesByGameId;

    @Override
    public User extractUser(String userId) {
        return userRepository.findById(userId)
                .orElseThrow(() -> new ValidationException("No user was found with the provided id."));
    }

    @Override
    public ListApp extractList(String listId) {
        return listAppRepository.findById(UUID.fromString(listId))
                .orElseThrow(() -> new ValidationException("No list was found with the provided id."));
    }

    @Override
    public Game extractGame(String gameId) {
        return gameRepository.findById(UUID.fromString(gameId))
                .orElseThrow(() -> new ValidationException("No game was found with the provided id."));
    }

    @Override
    public Console extractConsole(String consoleId, String gameId) {
        var console = consoleRepository.findById(UUID.fromString(consoleId))
                .orElseThrow(() -> new ValidationException("No console was found with the provided id."));

        var gameConsoles = getAllConsolesByGameId.getAllConsolesByGameId(null, gameId);
        var consoleIds = gameConsoles.getContent().stream().map(ConsoleReturnDTO::id).toList();

        if (!consoleIds.contains(console.getId())) {
            throw new ValidationException("The selected console is not associated with the game.");
        }

        return console;
    }

    @Override
    public GameList extractGameList(String gameListId) {
        var gameListIdUUID = UUID.fromString(gameListId);
        var gameList = gameListRepository.findById(gameListIdUUID)
                .orElseThrow(() -> new ValidationException("No game list found with the provided id."));
        return gameList;
    }
}
