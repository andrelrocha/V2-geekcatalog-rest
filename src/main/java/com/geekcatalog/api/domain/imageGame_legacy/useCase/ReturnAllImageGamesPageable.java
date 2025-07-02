package com.geekcatalog.api.domain.imageGame_legacy.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.imageGame_legacy.DTO.ImageGameReturnLegacyDTO;
import com.geekcatalog.api.domain.imageGame_legacy.ImageGameLegacy;
import com.geekcatalog.api.domain.imageGame_legacy.ImageGameLegacyRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

import java.util.ArrayList;

@Component
public class ReturnAllImageGamesPageable {

    @Autowired
    private ImageGameLegacyRepository repository;

    public Page<ImageGameReturnLegacyDTO> returnAllImages(Pageable pageable) {
        Page<ImageGameLegacy> imageGames = repository.findAll(pageable);

        if (imageGames.isEmpty()) {
            throw new ValidationException("Não foi encontrada nenhuma imagem para os jogos no sistema.");
        }

        ArrayList<ImageGameReturnLegacyDTO> dtos = new ArrayList<>();
        imageGames.forEach(imageGameLegacy -> {
            ImageGameReturnLegacyDTO dto = new ImageGameReturnLegacyDTO(imageGameLegacy.getGame().getId(), imageGameLegacy.getImage());
            dtos.add(dto);
        });

        return new PageImpl<>(dtos, pageable, imageGames.getTotalElements());
    }
}
