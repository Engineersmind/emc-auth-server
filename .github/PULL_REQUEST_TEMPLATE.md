## Summary

<!-- What does this PR do? 2-3 sentences max. Link the phase/plan it belongs to. -->

Closes #<!-- issue number if applicable -->

## Type of change

- [ ] Feature (new capability — maps to a roadmap phase/plan)
- [ ] Bug fix (non-breaking)
- [ ] Security fix
- [ ] Refactor (no behaviour change)
- [ ] Infra / CI / config change
- [ ] Documentation only

## Phase / Plan reference

<!-- e.g. Phase 3 — Plan 03-02: TOTP login flow -->

## Changes made

<!-- Bullet-point the key code changes -->

-
-

## Security considerations

<!-- Required for any change touching: auth/, middleware/, migrations/, JWT, sessions, passwords, cookies, CORS, rate limiting -->

- [ ] No new SQL queries without parameterized args
- [ ] No secrets or credentials in code or comments
- [ ] Auth middleware is not bypassed or weakened
- [ ] New migrations are backward-compatible (no destructive column drops without transition)
- [ ] Audit events added for any new security-relevant action
- [ ] Rate limiting behaviour unchanged or explicitly documented

## Test plan

<!-- How did you verify this works? -->

- [ ] `go build ./...` passes
- [ ] `go test ./...` passes
- [ ] Manual test: <!-- describe the flow you tested -->
- [ ] No regressions in existing endpoints (checked with health + login + me)

## Checklist

- [ ] Branch name follows convention (`feat/`, `fix/`, `chore/`, `docs/`, `hotfix/`)
- [ ] Commit messages are atomic and descriptive (`feat(03-02): ...`, `fix(jwt): ...`)
- [ ] Swagger annotations updated if handler signatures changed (`swag init`)
- [ ] README / ROADMAP updated if a phase plan is completed
- [ ] No `fmt.Println` or debug statements left in
