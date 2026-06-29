-- +goose Up
-- +goose StatementBegin
-- pg_uuidv7 is not bundled in standard postgres images.
-- UUIDv4 via gen_random_uuid() (pgcrypto, installed in 00001) is used instead.
SELECT 1;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 1;
-- +goose StatementEnd
