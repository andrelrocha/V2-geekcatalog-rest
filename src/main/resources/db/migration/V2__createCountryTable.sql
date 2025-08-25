CREATE TABLE country (
    id VARCHAR(36) PRIMARY KEY,
    name_common VARCHAR(100) NOT NULL,         -- Nome comum: "Brazil"
    name_official VARCHAR(255),                -- Nome oficial: "Federative Republic of Brazil"
    cca2 CHAR(2) NOT NULL UNIQUE,              -- ISO 3166-1 alpha-2 (ex: BR)
    cca3 CHAR(3) UNIQUE,                       -- ISO 3166-1 alpha-3 (ex: BRA)
    ccn3 CHAR(3) UNIQUE,                       -- ISO 3166-1 numeric (ex: 076)
    region VARCHAR(100),                       -- Continente ou região (ex: "Americas")
    subregion VARCHAR(100),                    -- Sub-região (ex: "South America")
    capital VARCHAR(100),                      -- Capital (ex: Brasília)
    international_prefix VARCHAR(5),           -- Prefixo internacional (ex: +55)
    country_code VARCHAR(5),                   -- Código telefônico DDI (ex: 55)
    currency_code CHAR(3),                     -- Código da moeda (ex: BRL)
    currency_name VARCHAR(100),                -- Nome da moeda (ex: "Brazilian Real")
    currency_symbol VARCHAR(10)                -- Símbolo monetário (ex: R$)
);