CREATE TABLE game_rating (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) REFERENCES app_user(id) ON DELETE CASCADE NOT NULL,
    game_id VARCHAR(36) REFERENCES game(id) ON DELETE CASCADE NOT NULL,
    rating INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE OR REPLACE FUNCTION set_updated_at_game_rating()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_set_updated_at_game_game_rating
BEFORE UPDATE ON game_rating
FOR EACH ROW
EXECUTE FUNCTION set_updated_at_game_rating();
