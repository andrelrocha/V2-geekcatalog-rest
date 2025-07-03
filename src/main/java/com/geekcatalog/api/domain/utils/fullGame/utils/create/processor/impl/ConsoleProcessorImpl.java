package com.geekcatalog.api.domain.utils.fullGame.utils.create.processor.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.consoles.DTO.ConsoleDTO;
import com.geekcatalog.api.domain.consoles.DTO.ConsoleReturnDTO;
import com.geekcatalog.api.domain.gameConsole.DTO.GameConsoleDTO;
import com.geekcatalog.api.domain.utils.API.IGDB.utils.ConsoleNameFormatterFromIGDB;
import com.geekcatalog.api.domain.utils.fullGame.utils.create.processor.ConsoleProcessor;
import com.geekcatalog.api.service.old.ConsoleService;
import com.geekcatalog.api.service.old.GameConsoleService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.geekcatalog.api.infra.utils.stringFormatter.StringFormatter.capitalizeEachWord;
import static com.geekcatalog.api.infra.utils.stringFormatter.StringFormatter.normalizeString;

@Service
public class ConsoleProcessorImpl implements ConsoleProcessor {
    @Autowired
    private ConsoleNameFormatterFromIGDB consoleNameFormatterFromIGDB;
    @Autowired
    private ConsoleService consoleService;
    @Autowired
    private GameConsoleService gameConsoleService;

    private static final Logger logger = LoggerFactory.getLogger(ConsoleProcessorImpl.class);

    @Override
    public void addGameConsole(List<ConsoleReturnDTO> newGameConsoles, String gameId, ConsoleReturnDTO console) {
        var gameConsoleDTO = new GameConsoleDTO(gameId, console.id().toString());
        var gameConsoleCreated = gameConsoleService.createGameConsole(gameConsoleDTO);
        newGameConsoles.add(new ConsoleReturnDTO(gameConsoleCreated.consoleId(), gameConsoleCreated.consoleName()));
    }

    @Override
    public Map<String, ConsoleReturnDTO> fetchConsolesWithId(List<String> normalizedConsoles) {
        ArrayList<ConsoleDTO> consoleDTOs = (ArrayList<ConsoleDTO>) normalizedConsoles.stream()
                .map(ConsoleDTO::new)
                .collect(Collectors.toList());

        return consoleService.getConsolesByName(consoleDTOs).stream()
                .collect(Collectors.toMap(
                        console -> normalizeString(console.name()),
                        console -> console
                ));
    }

    @Override
    public ConsoleReturnDTO handleConsoleCreationOrFetch(String consoleName, ConsoleReturnDTO console, String gameId) {
        if (console == null) {
            logger.info("Criando novo console '{}'", capitalizeEachWord(consoleName));
            console = consoleService.createConsole(new ConsoleDTO(capitalizeEachWord(consoleName)));
        } else {
            logger.info("Console '{}' já existe. Associando ao jogo ID: {}", console.name(), gameId);
        }
        return console;
    }

    @Override
    public List<String> normalizeAndConvertNames(List<String> consoles) {
        return consoleNameFormatterFromIGDB.normalizeAndConvertNames(consoles);
    }
}
