package com.geekcatalog.api.domain.utils.fullList.DTO;

import java.util.ArrayList;
import java.util.UUID;

public record FullListReturnDTO(UUID id, String name, String description, String ownerId, int count, ArrayList<String> gamesUri) {
}
