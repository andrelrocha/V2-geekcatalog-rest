package com.geekcatalog.api.service.impl;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.geekcatalog.api.domain.utils.API.OpenAI.DTO.GameNameDTO;
import com.geekcatalog.api.domain.utils.API.OpenAI.GPTQuery;
import com.geekcatalog.api.service.ChatGPTService;

@Service
public class ChatGPTServiceImpl implements ChatGPTService {
    @Autowired
    private GPTQuery gptQuery;

    @Override
    public String getGameInfo(GameNameDTO gameNameDTO) {
        return gptQuery.getGameInfo(gameNameDTO);
    }
}
