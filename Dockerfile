# ── Build stage ────────────────────────────────────────────────
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go.mod first; go.sum will be generated if absent
COPY go.mod ./
RUN go mod download -x 2>/dev/null; true

# Build binary — -mod=mod allows go to resolve and update go.sum during build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -mod=mod \
    -ldflags="-s -w -extldflags '-static'" \
    -o emc-auth-server ./cmd/server

# ── Runtime stage ───────────────────────────────────────────────
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata wget \
    && adduser -D -u 1001 appuser

WORKDIR /app

COPY --from=builder /app/emc-auth-server .

USER appuser

EXPOSE 8080

ENTRYPOINT ["./emc-auth-server"]
