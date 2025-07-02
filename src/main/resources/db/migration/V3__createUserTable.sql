CREATE TABLE app_user (
    id VARCHAR(36) PRIMARY KEY,
    email VARCHAR(100) NOT NULL UNIQUE,
    username VARCHAR(20) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    name VARCHAR(100) NOT NULL,
    phone VARCHAR(14),
    birthday DATE,
    country_id VARCHAR(36) NULL REFERENCES country(id) ON DELETE SET NULL,
    token_expiration TIMESTAMP,
    token_mail VARCHAR(255),
    access_failed_count INT DEFAULT 0,
    lockout_enabled BOOLEAN DEFAULT FALSE,
    lockout_end TIMESTAMP,
    two_factor_enabled BOOLEAN DEFAULT FALSE,
    refresh_token_enabled BOOLEAN DEFAULT false,
    theme VARCHAR(20),
    profile_pic_url VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_set_updated_at
BEFORE UPDATE ON app_user
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();