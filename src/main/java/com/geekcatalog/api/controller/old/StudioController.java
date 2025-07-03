package com.geekcatalog.api.controller.old;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.geekcatalog.api.domain.studios.DTO.StudioDTO;
import com.geekcatalog.api.domain.studios.DTO.StudioReturnDTO;
import com.geekcatalog.api.service.old.StudioService;

@RestController
@RequestMapping("/studios")
@Tag(name = "Studios Routes Mapped on Controller")
public class StudioController {
    @Autowired
    private StudioService studioService;

    @GetMapping("/all")
    public ResponseEntity<Page<StudioReturnDTO>> getAllStudios(@RequestParam(defaultValue = "0") int page,
                                                               @RequestParam(defaultValue = "" + Integer.MAX_VALUE) int size,
                                                               @RequestParam(defaultValue = "name") String sortField,
                                                               @RequestParam(defaultValue = "asc") String sortOrder) {
        var pageable = PageRequest.of(page, size, Sort.by(Sort.Direction.fromString(sortOrder), sortField));
        var studiosPageable = studioService.getAllStudios(pageable);
        return ResponseEntity.ok(studiosPageable);
    }

    @PostMapping("/create")
    public ResponseEntity createStudio(@RequestBody StudioDTO data) {
        var newStudio = studioService.createStudio(data);
        return ResponseEntity.status(HttpStatus.CREATED).body(newStudio);
    }
}
