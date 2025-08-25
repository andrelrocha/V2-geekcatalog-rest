package com.geekcatalog.api.domain.country;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface CountryRepository extends JpaRepository<Country, String> {
    @Query("SELECT c FROM Country c ORDER BY c.nameCommon ASC")
    Page<Country> findAllCountriesOrderedByName(Pageable pageable);

    @Query("SELECT c FROM Country c WHERE LOWER(TRIM(c.nameCommon)) IN :names")
    List<Country> findAllByNamesIgnoreCaseAndTrimmed(List<String> names);
}
