

CREATE TABLE users (
    id          INTEGER PRIMARY KEY,
    cpf         TEXT,
    full_name   TEXT,
    card_number TEXT,
    pin_md5     TEXT
);

INSERT INTO users VALUES (1, '000.000.000-00', 'Test User', '4111111111111111', '8621ffdbc5698829397d97767ac13db3');
