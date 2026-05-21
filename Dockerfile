# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod ./
RUN go mod download -x 2>/dev/null; true

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -mod=mod \
    -ldflags="-s -w -extldflags '-static'" \
    -o emc-auth-server ./cmd/server

# ── Runtime stage (distroless — no shell, no package manager) ─────────────────
# gcr.io/distroless/static-debian12:nonroot runs as uid 65532 (nonroot user).
# The static binary has no libc dependency — it runs in distroless/static directly.
# Image size: ~5MB vs ~20MB alpine. No shell means no interactive exploit surface.
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /app/emc-auth-server .

# distroless:nonroot already sets USER nonroot (uid 65532) — no USER directive needed.

EXPOSE 8080

ENTRYPOINT ["/app/emc-auth-server"]
