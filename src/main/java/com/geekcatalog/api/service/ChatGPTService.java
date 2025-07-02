package com.geekcatalog.api.service;

import com.geekcatalog.api.domain.utils.API.OpenAI.DTO.GameNameDTO;

public interface ChatGPTService {
    String getGameInfo(GameNameDTO gameNameDTO);
}
