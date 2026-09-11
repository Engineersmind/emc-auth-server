#!/bin/bash
# Assembles emails/*.html from the shared head/foot and a per-template body.
# Regenerate with: bash /tmp/build.sh
set -e
OUT="$(dirname "$0")"

eyebrow() { # $1=text $2=tint (danger|warn|success|info|muted)
  # Takes a semantic tint rather than a hex value, so each severity gets a class
  # of its own and the light @media block can map it to the light equivalent.
  # With one shared .eyebrow rule, every danger/warn/success label flattened to
  # grey in light mode and the severity signal was lost.
  local fg cls
  case "$2" in
    danger)  fg="#fb7185"; cls="eb-danger" ;;
    warn)    fg="#f0b429"; cls="eb-warn" ;;
    success) fg="#34d399"; cls="eb-success" ;;
    info)    fg="#a1a1aa"; cls="eb-info" ;;
    *)       fg="#8b8b95"; cls="eyebrow" ;;
  esac
  printf '                    <span class="%s" style="display:inline-block;font-family:%s;font-size:11px;font-weight:700;letter-spacing:0.08em;color:%s;text-transform:uppercase;">%s</span>\n' "$cls" "'Space Grotesk','Segoe UI',Helvetica,Arial,sans-serif" "$fg" "$1"
}
h1() {
  printf '                    <h1 class="text-primary" style="margin:10px 0 16px 0;font-family:%s;font-size:23px;line-height:1.3;color:#fafafa;font-weight:700;letter-spacing:-0.01em;">%s</h1>\n' "'Space Grotesk','Segoe UI',Helvetica,Arial,sans-serif" "$1"
}
p() {
  printf '                    <p class="text-body" style="margin:0 0 18px 0;font-family:%s;font-size:15px;line-height:1.65;color:#a1a1aa;">%s</p>\n' "'Space Grotesk','Segoe UI',Helvetica,Arial,sans-serif" "$1"
}
callout() { # $1=text $2=tint (danger|warn|success|info)
  # Each tint is the console's own paired bg / border / text triple, not a flat
  # panel with a coloured rule bolted on: --app-warn on --app-warn-bg is an
  # already-tested contrast pairing. The tint-* class is also the hook the dark
  # blocks in <head> target, so the panel re-tints instead of going muddy.
  local bg bd fg cls
  case "$2" in
    danger)  bg="#2a1620"; bd="#5c2233"; fg="#fb7185"; cls="tint-danger" ;;
    warn)    bg="#241f12"; bd="#5a4a1e"; fg="#f0b429"; cls="tint-warn" ;;
    success) bg="#12241d"; bd="#1e5a44"; fg="#34d399"; cls="tint-success" ;;
    *)       bg="#1f2229"; bd="#2f333c"; fg="#a1a1aa"; cls="tint-info" ;;
  esac
  cat <<C
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 22px 0;">
                      <tr>
                        <td class="$cls" style="background-color:$bg;border:1px solid $bd;border-radius:8px;padding:12px 14px;">
                          <span style="font-family:'Space Grotesk','Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;line-height:1.55;color:$fg;font-weight:500;">$1</span>
                        </td>
                      </tr>
                    </table>
C
}

button() { # $1=label
  # The btn class carries the dark inversion. In dark mode the console flips to a
  # BRIGHT lime with DARK text (--app-accent #bef264 / --app-on-accent #04140d);
  # keeping white-on-dark-lime would leave the one element that must always be
  # readable at poor contrast on a dark card.
  cat <<C
                    <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 20px 0;">
                      <tr>
                        <td class="btn" style="border-radius:6px;background-color:#bef264;">
                          <a href="{{.Link}}" target="_blank" style="display:inline-block;padding:13px 28px;font-family:'Space Grotesk','Segoe UI',Helvetica,Arial,sans-serif;font-size:15px;font-weight:700;color:#04140d;text-decoration:none;border-radius:6px;">$1</a>
                        </td>
                      </tr>
                    </table>
C
}

linkfallback() {
  cat <<'C'
                    <p class="text-muted" style="margin:0 0 8px 0;font-family:'Space Grotesk','Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;line-height:1.6;color:#8b8b95;">Or copy this link into your browser:</p>
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" class="bg-subtle" style="background-color:#1f2229;border:1px solid #23262d;border-radius:8px;margin:0 0 24px 0;">
                      <tr>
                        <td class="code-text" style="padding:11px 13px;font-family:'JetBrains Mono','Courier New',Courier,monospace;font-size:12px;line-height:1.5;color:#a1a1aa;word-break:break-all;">{{.Link}}</td>
                      </tr>
                    </table>
C
}

ttl() { # $1 = lead-in, e.g. "This link expires in"
  # Renders TTLMinutes in a unit a person would actually say.
  #
  # Earlier revisions printed {{.TTLMinutes}} raw, which produced "expires in
  # 1440 minutes" for the 24h verification token and "4320 minutes" for the 72h
  # invitation. internal/mailer/templates.go parses with a bare template.New and
  # no FuncMap, so there is no div or humanize helper available — only Go's
  # built-in comparisons — hence a ladder rather than arithmetic.
  #
  # Each branch is exact for a whole day/hour boundary and every band states
  # something true across its entire range, so editing InvitationTTL or
  # VerificationTokenTTL can move which branch fires but cannot make the
  # sentence false. That is the property the earlier hardcoded "3 days" behind a
  # ge-4320 threshold did not have.
  cat <<C
$1 {{if ge .TTLMinutes 5760}}4 days or more{{else if ge .TTLMinutes 4320}}3 days{{else if ge .TTLMinutes 2880}}2 days{{else if ge .TTLMinutes 1440}}24 hours{{else if ge .TTLMinutes 720}}12 hours{{else if ge .TTLMinutes 120}}a couple of hours{{else if ge .TTLMinutes 60}}1 hour{{else}}{{.TTLMinutes}} minutes{{end}}
C
}

rule() {
  printf '                    <hr style="border:none;border-top:1px solid #e0e0dc;margin:4px 0 18px 0;">\n'
}
note() {
  printf '                    <p class="text-faint" style="margin:0;font-family:%s;font-size:13px;line-height:1.6;color:#8b8b95;">%s</p>\n' "'Space Grotesk','Segoe UI',Helvetica,Arial,sans-serif" "$1"
}
row() { # $1=label $2=value-expr
  cat <<C
                        <tr>
                          <td class="text-muted stack" style="padding:7px 16px 7px 0;font-family:'Space Grotesk','Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;color:#8b8b95;white-space:nowrap;vertical-align:top;">$1</td>
                          <td class="text-primary stack" style="padding:7px 0;font-family:'Space Grotesk','Segoe UI',Helvetica,Arial,sans-serif;font-size:13px;font-weight:600;color:#fafafa;vertical-align:top;word-break:break-word;">$2</td>
                        </tr>
C
}
table_open() {
  printf '                    <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" class="bg-subtle" style="background-color:#1f2229;border:1px solid #23262d;border-radius:8px;margin:0 0 22px 0;">\n                      <tr><td style="padding:6px 16px;"><table role="presentation" width="100%%" cellpadding="0" cellspacing="0">\n'
}
table_close() {
  printf '                      </table></td></tr>\n                    </table>\n'
}

emit() { # $1=outfile $2=title $3=preheader ; body on stdin
  # Substitution splices with index()/substr() rather than sed or gsub. Both of
  # those treat & in the REPLACEMENT as "the whole match", so every &mdash; in a
  # title came out as __TITLE__mdash;. substr() has no metacharacters at all.
  local body
  body=$(cat)
  awk -v t="$2" -v p="$3" '
    function splice(line, tok, val,    i) {
      while ((i = index(line, tok)) > 0) {
        line = substr(line, 1, i - 1) val substr(line, i + length(tok))
      }
      return line
    }
    {
      $0 = splice($0, "__TITLE__", t)
      $0 = splice($0, "__PREHEADER__", p)
      print
    }
  ' "$(dirname "$0")"/head.part > "$OUT/$1"
  printf '%s\n' "$body" >> "$OUT/$1"
  cat "$(dirname "$0")"/foot.part >> "$OUT/$1"
  echo "  $1"
}

echo "Writing templates:"

# ── 01 email_verification ─────────────────────────────────────────────────────
{
  eyebrow "Verify your email" "muted"
  h1 "Confirm your email address"
  p "Thanks for creating an account{{if .AppName}} with {{.AppName}}{{end}}. Confirm this is your address to activate your account."
  # VerificationTokenTTL is 24h, so TTLMinutes is 1440. "1440 minutes" is not a
  # sentence anyone should receive; no FuncMap exists to divide, so the threshold
  # is matched to the constant. Change both together.
  callout "&#9888;&nbsp; $(ttl "This link expires in")" "warn"
  button "Confirm email address"
  linkfallback
  rule
  note "If you did not create this account, you can ignore this email &mdash; nothing will be activated."
} | emit "01_email_verification.html" \
  "{{if .AppName}}{{.AppName}}{{else}}{{.ProductName}}{{end}} &mdash; Confirm your email address" \
  "Confirm your email address{{if .AppName}} for {{.AppName}}{{end}} &mdash; expires in {{if ge .TTLMinutes 1440}}24 hours{{else}}{{.TTLMinutes}} minutes{{end}}."

# ── 02 password_reset ─────────────────────────────────────────────────────────
{
  eyebrow "Password reset" "muted"
  h1 "Reset your password"
  p "We received a request to reset the password for your account{{if .AppName}} with {{.AppName}}{{end}}. Choose a new password to continue."
  callout "&#9888;&nbsp; $(ttl "This link expires in"), and can be used once" "warn"
  button "Reset password"
  linkfallback
  rule
  note "If you did not request this, your password is unchanged and no action is needed. If you receive these repeatedly, someone may know your address &mdash; consider enabling two-factor authentication."
} | emit "02_password_reset.html" \
  "{{.ProductName}} &mdash; Reset your password" \
  "Reset your password &mdash; this link expires in {{.TTLMinutes}} minutes."

# ── 03 welcome ────────────────────────────────────────────────────────────────
{
  eyebrow "Account ready" "success"
  h1 "Welcome{{if .Name}}, {{.Name}}{{end}}"
  p "Your email address is verified and your account{{if .AppName}} for {{.AppName}}{{end}} is ready to use."
  p "For the best protection, we recommend enabling two-factor authentication in your account settings."
  rule
  note "Thank you for choosing {{if .AppName}}{{.AppName}}{{else}}{{.ProductName}}{{end}}."
} | emit "03_welcome.html" \
  "Welcome to {{if .AppName}}{{.AppName}}{{else}}{{.ProductName}}{{end}}" \
  "Your email address is verified and your account is ready to use."

# ── 04 mfa_code ───────────────────────────────────────────────────────────────
{
  eyebrow "Sign-in verification" "muted"
  h1 "Your verification code"
  p "Enter this code to finish signing in{{if .AppName}} to {{.AppName}}{{end}}:"
  cat <<'C'
                    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 14px 0;">
                      <tr>
                        <td align="center" class="bg-subtle" style="background-color:#1f2229;border:1px solid #23262d;border-radius:8px;padding:20px;">
                          <span class="text-primary" style="font-family:'Courier New',Courier,monospace;font-size:30px;font-weight:700;letter-spacing:8px;color:#fafafa;">{{.Code}}</span>
                        </td>
                      </tr>
                    </table>
C
  callout "&#9888;&nbsp; $(ttl "This code expires in")" "warn"
  rule
  note "Never share this code. {{.ProductName}} staff will never ask you for it. If you were not signing in, change your password &mdash; someone may have it."
} | emit "04_mfa_code.html" \
  "{{if .AppName}}Your {{.AppName}} verification code{{else}}Your verification code{{end}}" \
  "Your one-time verification code expires in {{.TTLMinutes}} minutes."

# ── 05 magic_link ─────────────────────────────────────────────────────────────
{
  eyebrow "Sign in" "muted"
  h1 "Your sign-in link"
  p "Use the button below to sign in to {{if .AppName}}{{.AppName}}{{else}}your account{{end}}. No password required."
  callout "&#9888;&nbsp; $(ttl "Valid for"), and can be used once" "warn"
  button "Sign in"
  linkfallback
  rule
  note "Treat this link like a password &mdash; anyone who opens it can sign in as you. If you did not request it, ignore this email."
} | emit "05_magic_link.html" \
  "Sign in to {{if .AppName}}{{.AppName}}{{else}}your account{{end}}" \
  "Your single-use sign-in link expires in {{.TTLMinutes}} minutes."

# ── 06 password_changed ───────────────────────────────────────────────────────
{
  eyebrow "Security notice" "info"
  h1 "Your password was changed"
  p "The password for your account{{if .AppName}} with {{.AppName}}{{end}} was changed successfully. All other sessions have been signed out."
  callout "&#9888;&nbsp; If you did not make this change, act now &mdash; reset your password and contact support" "danger"
  rule
  note "You are receiving this because a password change is worth telling you about even when it was you. It is how an unauthorised change gets noticed."
} | emit "06_password_changed.html" \
  "{{.ProductName}} &mdash; Your password was changed" \
  "Confirmation that your account password was just changed."

# ── 07 user_invitation ────────────────────────────────────────────────────────
{
  eyebrow "You are invited" "muted"
  h1 "{{if .InviterName}}{{.InviterName}} invited you{{else}}You have been invited{{end}}"
  p "{{if .InviterName}}{{.InviterName}} has invited you{{else}}You have been invited{{end}} to join {{if .AppName}}{{.AppName}}{{else}}{{.ProductName}}{{end}}{{if .Name}}, {{.Name}}{{end}}. Accept the invitation to set your password and activate your account."
  # 4320 minutes reads absurdly; no FuncMap exists to divide, so the thresholds
  # are matched to InvitationTTL (72h). Change both together.
  callout "&#9888;&nbsp; $(ttl "This invitation expires in")" "warn"
  button "Accept invitation"
  linkfallback
  rule
  note "If you were not expecting this invitation, you can ignore it &mdash; no account will be created until you accept."
} | emit "07_user_invitation.html" \
  "{{if .InviterName}}{{.InviterName}} invited you to {{end}}{{if .AppName}}{{.AppName}}{{else}}{{.ProductName}}{{end}}" \
  "{{if .InviterName}}{{.InviterName}} has invited you{{else}}You have been invited{{end}} to join {{if .AppName}}{{.AppName}}{{else}}{{.ProductName}}{{end}}."

# ── 08 change_email (2 variants) ──────────────────────────────────────────────
{
  printf '{{if eq .Reason "email_changed"}}\n'
  eyebrow "Security alert" "danger"
  h1 "Your account email was changed"
  p "The email address on your account{{if .AppName}} for {{.AppName}}{{end}} was changed to <strong class=\"text-primary\" style=\"color:#fafafa;\">{{.NewEmail}}</strong>. This is the last message this address will receive."
  callout "&#9888;&nbsp; If you did not authorise this, your account may be compromised. Reset your password immediately." "danger"
  button "Reset password"
  linkfallback
  rule
  note "You are receiving this at your previous address on purpose: it is the only way you would find out if someone else moved your account."
  printf '{{else}}\n'
  eyebrow "Confirm your email" "muted"
  h1 "Confirm your new email address"
  p "We received a request to move an account to this address. Confirm it belongs to you to complete the change."
  callout "&#9888;&nbsp; $(ttl "This link expires in")" "warn"
  button "Confirm email address"
  linkfallback
  rule
  note "If you did not request this, ignore this email &mdash; the account&rsquo;s address stays as it is."
  printf '{{end}}\n'
} | emit "08_change_email.html" \
  '{{if eq .Reason "email_changed"}}Security alert &mdash; your account email was changed{{else}}Confirm your new email address{{end}}' \
  '{{if eq .Reason "email_changed"}}The email address on your account was changed.{{else}}Confirm your new email address to complete the change.{{end}}'

# ── 09 blocked_account (5 variants) ───────────────────────────────────────────
{
  printf '{{if eq .Reason "suspicious_login"}}\n'
  eyebrow "Security alert" "danger"
  h1 "Unusual sign-in to your account"
  p "Someone signed in to your account{{if .AppName}} for {{.AppName}}{{end}} from a device or location we do not recognise. The sign-in succeeded and your account is not blocked."
  callout "&#9888;&nbsp; If this was not you, change your password now &mdash; whoever signed in still has access" "danger"
  button "Change password"
  linkfallback
  rule
  note "If it was you, no action is needed. We send this because an unrecognised sign-in is the earliest sign of a stolen password."

  printf '{{else if eq .Reason "failed_attempts_warning"}}\n'
  eyebrow "Security alert" "warn"
  h1 "Repeated failed sign-in attempts"
  p "There have been several failed attempts to sign in to your account{{if .AppName}} for {{.AppName}}{{end}}. Your account is still active and has not been locked."
  p "If this was you and you have forgotten your password, reset it below. If it was not, someone is guessing &mdash; we recommend changing your password and enabling two-factor authentication."
  button "Reset password"
  linkfallback
  rule
  note "Continued failures will temporarily lock sign-in to protect the account."

  printf '{{else if eq .Reason "soft_locked"}}\n'
  eyebrow "Temporary lock" "warn"
  h1 "Sign-in temporarily locked"
  p "After repeated failed attempts, sign-ins to your account{{if .AppName}} for {{.AppName}}{{end}} are paused as a precaution. Your account has not been blocked and no action is required."
  callout "&#9888;&nbsp; $(ttl "Access is restored automatically in about")" "warn"
  p "If you have forgotten your password, you can reset it now instead of waiting."
  button "Reset password"
  linkfallback
  rule
  note "If these attempts were not yours, change your password once access is restored."

  printf '{{else if eq .Reason "admin"}}\n'
  eyebrow "Account blocked" "danger"
  h1 "Your account has been blocked"
  p "An administrator has blocked access to your account{{if .AppName}} for {{.AppName}}{{end}}. Only an administrator can restore it."
  p "Contact your administrator to have access restored. If you believe your password was compromised, you can reset it below &mdash; though this will not unblock the account."
  button "Reset password"
  linkfallback
  rule
  note "This was an administrative action, not an automatic one. Your sign-in history did not cause it."

  printf '{{else}}\n'
  eyebrow "Account blocked" "danger"
  h1 "Your account has been blocked"
  p "Access to your account{{if .AppName}} for {{.AppName}}{{end}} was blocked after repeated failed sign-in attempts. This protects the account while we are unsure who was trying to get in."
  callout "&#9888;&nbsp; $(ttl "This unblock link expires in"), and can be used once" "warn"
  button "Unblock account"
  linkfallback
  printf '{{if .RetryMinutes}}\n'
  note "Alternatively, access is restored automatically in about {{.RetryMinutes}} minutes."
  printf '{{end}}\n'
  rule
  note "If these attempts were not yours, change your password after unblocking &mdash; someone is trying to guess it."
  printf '{{end}}\n'
} | emit "09_blocked_account.html" \
  '{{if eq .Reason "suspicious_login"}}Security alert &mdash; unusual sign-in to your account{{else if eq .Reason "failed_attempts_warning"}}Security alert &mdash; failed sign-in attempts{{else if eq .Reason "soft_locked"}}Sign-in temporarily locked{{else}}Your account has been blocked{{end}}' \
  '{{if eq .Reason "suspicious_login"}}An unrecognised device signed in to your account.{{else if eq .Reason "failed_attempts_warning"}}Several failed sign-in attempts on your account.{{else if eq .Reason "soft_locked"}}Sign-in is temporarily paused as a precaution.{{else}}Your account was blocked after repeated failed sign-in attempts.{{end}}'

# ── 10 password_breach ────────────────────────────────────────────────────────
{
  eyebrow "Security alert" "danger"
  h1 "Your password appeared in a data breach"
  p "The password on your account{{if .AppName}} for {{.AppName}}{{end}} appears in a public list of passwords exposed in third-party breaches. Choose a new one as soon as you can."
  callout "&#9888;&nbsp; This does not mean your account was accessed &mdash; but this password is now known to attackers" "danger"
  button "Change password"
  linkfallback
  rule
  note "The breach was elsewhere, not at {{.ProductName}}: we compare passwords against published breach data without ever sending yours anywhere. If you use this password on other sites, change it there too."
} | emit "10_password_breach.html" \
  "{{.ProductName}} &mdash; Please change your password" \
  "Your password appears in a known data breach. Please choose a new one."

# ── 11 tenant_lockout_alert (operators) ───────────────────────────────────────
{
  eyebrow "Security alert" "danger"
  h1 "{{.Count}} accounts locked in {{.TTLMinutes}} minutes"
  p "<strong class=\"text-primary\" style=\"color:#fafafa;\">{{.Count}} accounts</strong>{{if .TenantName}} in {{.TenantName}}{{end}} locked after repeated failed sign-ins inside one {{.TTLMinutes}}-minute window."
  p "A cluster this size is usually an automated password-guessing attack rather than users forgetting passwords. Every affected account locked itself, so they are protected &mdash; but the source is worth confirming."
  table_open
  row "Accounts locked" "{{.Count}}"
  row "Window" "{{.TTLMinutes}} minutes"
  printf '{{if .TenantName}}'; row "Tenant" "{{.TenantName}}"; printf '{{end}}'
  printf '{{if .AppName}}'; row "Application" "{{.AppName}}"; printf '{{end}}'
  table_close
  button "Review locked accounts"
  linkfallback
  rule
  note "Locked accounts are restored automatically when their locks expire, or you can unlock any of them now from the users page. You receive this because you are accountable for this tenant; further spikes are suppressed for one hour."
} | emit "11_tenant_lockout_alert.html" \
  "Security alert &mdash; {{.Count}} accounts locked{{if .TenantName}} in {{.TenantName}}{{end}}" \
  "{{.Count}} accounts locked after repeated failed sign-ins &mdash; possible credential-stuffing attack."

# ── 12 admin_activity (operators) ─────────────────────────────────────────────
{
  eyebrow "Administrator activity" "info"
  # The h1 names WHERE, the paragraph names who and what. Putting the action in
  # both made the two lines read as a duplicated sentence, and the role cannot
  # take an article ("A owner") from a template.
  # No article before the role: "A owner" is wrong and Go templates cannot pick
  # a/an from the value. The role reads fine as a bare noun phrase.
  h1 "Privileged action in {{if .TenantName}}{{.TenantName}}{{else}}your tenant{{end}}"
  p "<strong class=\"text-primary\" style=\"color:#fafafa;\">{{.ActorEmail}}</strong>{{if .ActorRole}} ({{.ActorRole}}){{end}} {{.ActionLabel}}{{if gt .Count 1}} &mdash; {{.Count}} times in quick succession{{end}}."
  table_open
  row "Performed by" "{{.ActorEmail}}"
  printf '{{if .ActorRole}}'; row "Role" "{{.ActorRole}}"; printf '{{end}}'
  printf '{{if .TenantName}}'; row "Tenant" "{{.TenantName}}"; printf '{{end}}'
  printf '{{if .ResourceName}}'; row "Resource" "{{.ResourceName}}"; printf '{{end}}'
  printf '{{if .OccurredAt}}'; row "When" "{{.OccurredAt}}"; printf '{{end}}'
  printf '{{if .IPAddress}}'; row "From IP" "{{.IPAddress}}"; printf '{{end}}'
  printf '{{if gt .Count 1}}'; row "Occurrences" "{{.Count}}"; printf '{{end}}'
  table_close
  printf '{{if .Link}}\n'
  button "Review in monitoring"
  linkfallback
  printf '{{end}}\n'
  rule
  note "You receive this because you are accountable for this tenant. If this change was not expected, review it now &mdash; a privileged action you cannot account for is how a compromised administrator session is caught."
} | emit "12_admin_activity.html" \
  "{{if .ActorRole}}{{.ActorRole}}{{else}}An administrator{{end}} {{.ActionLabel}}{{if .TenantName}} in {{.TenantName}}{{end}}" \
  "{{.ActorEmail}}{{if .ActorRole}} ({{.ActorRole}}){{end}} {{.ActionLabel}}{{if .TenantName}} in {{.TenantName}}{{end}}."

# ── 13 access_changed (the affected administrator) ────────────────────────────
{
  eyebrow "Your access" "info"
  h1 "Your administrator access has changed"
  # ActionLabel here is already a full second-person sentence from
  # notify/catalog.go subjectLabels ("Your administrator access was withdrawn"),
  # NOT the verb phrase admin_activity uses. So it stands alone and the actor
  # follows in its own sentence: ", by dana" appended to a sentence is a splice.
  p "{{.ActionLabel}}.{{if .ActorEmail}} This was done by <strong class=\"text-primary\" style=\"color:#fafafa;\">{{.ActorEmail}}</strong>{{if .ActorRole}} ({{.ActorRole}}){{end}}.{{end}}"
  table_open
  printf '{{if .TenantName}}'; row "Tenant" "{{.TenantName}}"; printf '{{end}}'
  printf '{{if .ResourceName}}'; row "Applications" "{{.ResourceName}}"; printf '{{end}}'
  printf '{{if .ActorEmail}}'; row "Changed by" "{{.ActorEmail}}"; printf '{{end}}'
  printf '{{if .OccurredAt}}'; row "When" "{{.OccurredAt}}"; printf '{{end}}'
  table_close
  p "You will see the change the next time you sign in."
  rule
  note "If you were not expecting this, contact whoever administers this tenant. We tell you directly so that access being removed is something you are told about, rather than something you discover by being refused."
} | emit "13_access_changed.html" \
  "Your administrator access{{if .TenantName}} in {{.TenantName}}{{end}} has changed" \
  "{{.ActionLabel}}{{if .ActorEmail}} &mdash; by {{.ActorEmail}}{{end}}."

# ── 14 provider_test (diagnostic) ─────────────────────────────────────────────
{
  eyebrow "Configuration test" "success"
  h1 "Your email settings work"
  p "This is a test message sent from {{.ProductName}}{{if .AppName}} for {{.AppName}}{{end}}. Receiving it confirms your sender, credentials and delivery route are configured correctly."
  callout "&#10003;&nbsp; No action is required. This is not a real notification and contains no links to follow." "success"
  p "If it landed in spam, check your SPF, DKIM and DMARC records for the sending domain &mdash; delivery succeeded, but reputation still decides the inbox."
  rule
  note "This message is deliberately not one of the customisable templates: a configuration test has to announce itself as a test, so it can never be mistaken for a genuine verification or reset."
} | emit "14_provider_test.html" \
  "{{.ProductName}} &mdash; Test email" \
  "Test message confirming your email provider settings are working."

echo "done."
