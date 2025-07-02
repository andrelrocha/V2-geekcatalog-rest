package com.geekcatalog.api.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.consoles.DTO.ConsoleDTO;
import com.geekcatalog.api.domain.consoles.DTO.ConsoleReturnDTO;
import com.geekcatalog.api.domain.consoles.useCase.CreateConsole;
import com.geekcatalog.api.domain.consoles.useCase.GetAllConsoles;
import com.geekcatalog.api.domain.consoles.useCase.GetAllConsolesByGameId;
import com.geekcatalog.api.domain.consoles.useCase.GetConsolesIdByName;
import com.geekcatalog.api.service.ConsoleService;

import java.util.ArrayList;
import java.util.List;

@Service
public class ConsoleServiceImpl implements ConsoleService {
    @Autowired
    private CreateConsole createConsole;
    @Autowired
    private GetAllConsoles getAllConsoles;
    @Autowired
    private GetAllConsolesByGameId getAllConsolesByGameId;
    @Autowired
    private GetConsolesIdByName getConsolesIdByName;

    @Override
    public ConsoleReturnDTO createConsole(ConsoleDTO data) {
        return createConsole.createConsole(data);
    }

    @Override
    public Page<ConsoleReturnDTO> getAllConsoles(Pageable pageable) {
        var consoles = getAllConsoles.getAllConsoles(pageable);
        return consoles;
    }

    @Override
    public Page<ConsoleReturnDTO> getAllConsolesByGameId(Pageable pageable, String gameId) {
        return getAllConsolesByGameId.getAllConsolesByGameId(pageable, gameId);
    }

    @Override
    public List<ConsoleReturnDTO> getConsolesByName(ArrayList<ConsoleDTO> data) {
        return getConsolesIdByName.getConsolesByName(data);
    }
}
