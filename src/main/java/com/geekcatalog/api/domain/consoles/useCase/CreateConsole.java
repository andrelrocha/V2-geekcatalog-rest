package com.geekcatalog.api.domain.consoles.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.consoles.Console;
import com.geekcatalog.api.domain.consoles.ConsoleRepository;
import com.geekcatalog.api.domain.consoles.DTO.ConsoleDTO;
import com.geekcatalog.api.domain.consoles.DTO.ConsoleReturnDTO;
import com.geekcatalog.api.infra.exceptions.ValidationException;

@Component
public class CreateConsole {
    @Autowired
    private ConsoleRepository consoleRepository;

    public ConsoleReturnDTO createConsole(ConsoleDTO data) {
        var console = consoleRepository.findByName(data.name());

        if (console != null) {
            throw new ValidationException("A console with the provided name already exists");
        }

        var newConsole = new Console(data);
        var consoleOnDB = consoleRepository.save(newConsole);

        return new ConsoleReturnDTO(consoleOnDB);
    }
}
