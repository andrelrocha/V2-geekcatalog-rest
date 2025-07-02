package com.geekcatalog.api.domain.studios.useCase;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.geekcatalog.api.domain.country.CountryRepository;
import com.geekcatalog.api.domain.studios.DTO.CreateStudioDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioReturnDTO;
import com.geekcatalog.api.domain.studios.Studio;
import com.geekcatalog.api.domain.studios.StudioRepository;
import com.geekcatalog.api.infra.exceptions.ValidationException;

@Component
public class CreateStudio {
    @Autowired
    private StudioRepository repository;

    @Autowired
    private CountryRepository countryRepository;

    public StudioReturnDTO createStudio(StudioDTO data) {
        var studioExists = repository.existsByNameAndCountry(data.name(), data.countryId());

        if (studioExists) {
            throw new ValidationException("A studio with the given name and country already exists");
        }

        var country = countryRepository.findById(data.countryId())
                .orElseThrow(() -> new ValidationException("No country found with the provided ID during studio creation"));

        var createDTO = new CreateStudioDTO(data.name(), country);

        var studio = new Studio(createDTO);

        var studioOnDB = repository.save(studio);

        return new StudioReturnDTO(studioOnDB);
    }
}
