-- +goose Up
-- +goose StatementBegin

-- Email delivery becomes opt-in per application.
--
-- Until now a new application inherited every built-in template as ENABLED,
-- because email_templates holds only overrides and absence means "send the
-- built-in default" (migration 00060). Creating an application therefore
-- switched on thirteen kinds of outbound mail that nobody had asked for.
--
-- The product decision is the opposite: an application should send nothing until
-- its operator turns a template on and configures it. A new app is a blank
-- slate, and email — which costs money, needs a verified sender, and reaches
-- real inboxes — is not something to start doing by default.
--
-- HOW IT IS EXPRESSED
--
-- One row per (application, template_type) with is_active = false, and EMPTY
-- bodies.
--
-- Empty rather than a copy of the built-in default, which is the important part.
-- EmailTemplateService.Resolve filters `is_active = true`, so an inactive row is
-- invisible to content resolution and the built-in default still wins the moment
-- the row is enabled. Seeding the default's CONTENT instead would fork it:
-- frozen at today's wording, never receiving later improvements — exactly the
-- trap the admin UI warns about when disabling a default. IsTypeEnabled reads
-- is_active alone, so the suppression works while the content stays live.
--
-- Enabling is then a one-field flip: the operator toggles the row on and either
-- writes their own copy or keeps the maintained default.
--
-- SCOPE OF THIS MIGRATION
--
-- Existing applications are deliberately NOT touched. They are in production
-- sending verification and reset mail today, and retroactively suppressing that
-- would break live signup and account recovery with no operator action. This
-- changes what a NEW application starts with; CreateApplication seeds the same
-- rows going forward.

-- Widen the content columns' contract: a suppression row carries no body.
-- subject/html_body are NOT NULL with no default, so the seeder supplies ''.
-- No schema change is needed — this comment records why empty strings are
-- legitimate here rather than a sign of a broken write.
COMMENT ON TABLE email_templates IS
  'Per-scope email template overrides. A row with is_active = false and empty bodies is a SUPPRESSION marker: it disables sending for that (scope, type) without overriding content, so the maintained built-in default returns as soon as the row is enabled. Resolve() ignores inactive rows; IsTypeEnabled() reads is_active.';

-- +goose StatementEnd


-- +goose Down
-- +goose StatementBegin

COMMENT ON TABLE email_templates IS NULL;

-- +goose StatementEnd
