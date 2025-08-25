package com.geekcatalog.api.domain.country;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Table(name = "country")
@Entity(name = "Country")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class Country {
    @Id
    @Column(name = "id", nullable = false, length = 36, updatable = false)
    private String id;

    @NotNull
    @Column(name = "name_common", nullable = false, length = 100)
    private String nameCommon;

    @Column(name = "name_official")
    private String nameOfficial;

    @NotNull
    @Column(name = "cca2", nullable = false, length = 2, unique = true)
    private String cca2;

    @Column(name = "cca3", length = 3, unique = true)
    private String cca3;

    @Column(name = "ccn3", length = 3, unique = true)
    private String ccn3;

    @Column(name = "region", length = 100)
    private String region;

    @Column(name = "subregion", length = 100)
    private String subregion;

    @Column(name = "capital", length = 100)
    private String capital;

    @Column(name = "international_prefix", length = 5)
    private String internationalPrefix;

    @Column(name = "country_code", length = 5)
    private String countryCode;

    @Column(name = "currency_code", length = 3)
    private String currencyCode;

    @Column(name = "currency_name", length = 100)
    private String currencyName;

    @Column(name = "currency_symbol", length = 10)
    private String currencySymbol;

    @PrePersist
    public void onCreate() {
        this.id = UUID.randomUUID().toString().toUpperCase();
    }

}
