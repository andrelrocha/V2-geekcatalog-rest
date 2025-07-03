package com.geekcatalog.api.controller.old;

import com.geekcatalog.api.dto.utils.ApiResponseDTO;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.geekcatalog.api.service.old.CountryService;

@RestController
@RequestMapping("/country")
@Tag(name = "Country Routes Mapped on Controller")
public class CountryController {
    @Autowired
    private CountryService countryService;

    @GetMapping("/all")
    public ResponseEntity getAllCountriesPageable (@RequestParam(defaultValue = "0") int page,
                                                   @RequestParam(defaultValue = "240") int size,
                                                   @RequestParam(defaultValue = "nameCommon") String sortField,
                                                   @RequestParam(defaultValue = "asc") String sortOrder) {
        var pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortOrder), sortField));
        var countriesPageable = countryService.getAllCountries(pageable);
        return ResponseEntity.ok(ApiResponseDTO.success(countriesPageable));
    }
}
