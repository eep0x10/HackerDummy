-- wallet.db — shipped/seeded plaintext SQLite (NO SQLCipher, NO encryption).
-- Stored unencrypted under /data/data/com.storagecrypt.app/databases/wallet.db
CREATE TABLE users (
    id          INTEGER PRIMARY KEY,
    cpf         TEXT,   -- PII, cleartext
    full_name   TEXT,   -- PII, cleartext
    card_number TEXT,   -- full PAN, cleartext
    pin_md5     TEXT    -- unsalted MD5 of the user PIN
);
-- seed
INSERT INTO users VALUES (1, '000.000.000-00', 'Test User', '4111111111111111', '8621ffdbc5698829397d97767ac13db3');
