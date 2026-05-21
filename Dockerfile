# ── Stage 1: Build React SPA ──────────────────────────────────────────────────
FROM node:20-alpine AS ui-builder

WORKDIR /app/ui

COPY ui/package.json ui/package-lock.json* ./
RUN npm ci --silent

COPY ui/ ./
# Output goes to ../internal/ui/dist (relative to ui/) = /app/internal/ui/dist
RUN npm run build

# ── Stage 2: Build Go binary ──────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Copy the built SPA from stage 1 into the Go source tree so embed.FS picks it up
COPY --from=ui-builder /app/internal/ui/dist ./internal/ui/dist

RUN CGO_ENABLED=0 GOOS=linux go build \
    -mod=mod \
    -ldflags="-s -w -extldflags '-static'" \
    -o emc-auth-server ./cmd/server

# ── Stage 3: Runtime (distroless — no shell, no package manager) ──────────────
# gcr.io/distroless/static-debian12:nonroot runs as uid 65532 (nonroot user).
# The static binary has no libc dependency — it runs in distroless/static directly.
# Image size: ~5MB vs ~20MB alpine. No shell means no interactive exploit surface.
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

COPY --from=builder /app/emc-auth-server .

# distroless:nonroot already sets USER nonroot (uid 65532) — no USER directive needed.

EXPOSE 8080

ENTRYPOINT ["/app/emc-auth-server"]
