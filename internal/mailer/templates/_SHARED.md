# Email template design system

Shared conventions for every file in this directory. Read this before editing one.

## Theme — the admin console's own tokens

Read from `:root` in the built stylesheet (`emc-auth-frontend/dist/assets/index-*.css`),
not approximated. These are the LIGHT theme values; emails force light.

| Console token | Value | Use in email |
|---|---|---|
| `--app-bg` | `#f8f8f7` | page ground (warm off-white, NOT a cool gray) |
| `--app-surface` | `#ffffff` | card |
| `--app-surface-2` | `#f4f4f2` | inset panels, link boxes |
| `--app-border` | `#e0e0dc` | card and panel borders |
| `--app-text` | `#18181b` | headings, values |
| `--app-text-2` | `#52525b` | body copy |
| `--app-text-muted` | `#63636b` | labels, secondary copy |
| `--app-accent` | `#4d7c0f` | primary button (lime) |
| `--app-on-accent` | `#ffffff` | button label |
| `--app-radius` | `8px` | card and panel radius |
| `--app-font-sans` | Space Grotesk | all text |
| `--app-font-mono` | JetBrains Mono | codes, URLs |

Semantic tints use the console's matched bg/border/text triples, never a flat
gray panel with a coloured rule bolted on:

| Tint | bg | border | text | Meaning |
|---|---|---|---|---|
| `danger` | `#fdf1f3` | `#f2c9d2` | `#be123c` | a security incident to act on now |
| `warn` | `#fbf6e9` | `#e8d5a4` | `#a16207` | a caution or a deadline |
| `success` | `#ecfdf5` | `#a7f3d0` | `#047857` | a confirmation |
| `info` | `#f1f1ef` | `#cfcfc9` | `#52525b` | an operator notice |

**Webfonts are named, never fetched.** Space Grotesk and JetBrains Mono lead each
stack and fall back to the same system fonts the app uses. No `` or
`<link>`: Outlook desktop ignores `-face`, and a blocking font request in an
email is a tracking vector.

## Structure

Every template is the same skeleton, so a reader learns it once:

1. **Preheader** — hidden inbox preview line. Never empty; an empty one leaks raw markup into the inbox list.
2. **Logo band** — `{{.LogoURL}}` when branding is configured, else a wordmark. No emoji glyph: it renders as mojibake in several clients and as tofu in others.
3. **Card** — eyebrow label, `<h1>`, body, optional callout, action button, plaintext link fallback, rule, closing note.
4. **Footer** — automated-message notice and copyright.

## Rules

- **Tables for layout.** Outlook uses Word for rendering; flex and grid do not exist there.
- **Inline styles on every element.** Gmail strips `<style>` blocks in some contexts, so the `<style>` head is progressive enhancement only — never the sole source of a colour.
- **Light theme forced** via `color-scheme` meta, with `[data-ogsc]`/`[data-ogsb]` overrides for clients that auto-invert anyway.
- **Every button repeats its URL** as selectable text. Corporate gateways rewrite or strip `<a href>`; without the fallback the email becomes a dead end.
- **HTML entities, not literal glyphs** (`&#9888;` not `⚠`). The originals in this project were double-encoded (`â`), which is what a literal glyph looks like when UTF-8 is read as Latin-1.
- **600px max width**, collapsing to 100% under 600px with reduced padding.
- **No external assets** except `{{.LogoURL}}`. No web fonts, no tracking pixels, no background images.

## Variables

From `mailer.TemplateData` (internal/mailer/templates.go). A field absent for a
template is empty, so guard every optional one with `{{if}}`:

`ProductName` `LogoURL` `AppName` `Link` `Code` `TTLMinutes` `Name` `Email`
`InviterName` `Reason` `NewEmail` `ActionLabel` `ActorEmail` `ActorRole`
`TenantName` `ResourceName` `OccurredAt` `IPAddress` `Count` `RetryMinutes`

`ProductName` is always set. `AppName` is empty for tenant-scope sends — hence
the `{{if .AppName}}{{.AppName}}{{else}}{{.ProductName}}{{end}}` idiom.

## Audience

| Files | Audience | Voice |
|---|---|---|
| 01–10 | End users | Second person, plain language, no internal terms |
| 11–12 | Owners, co-owners, platform admins | Operator language; facts in a detail table |
| 13 | The administrator whose own access changed | Second person about their own access |
| 14 | The admin who clicked "send test" | Announces itself as a test |
