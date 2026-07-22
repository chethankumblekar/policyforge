# Multi-stage build: compile a static binary, then ship it in a minimal
# runtime image. Templates are embedded via go:embed at compile time, so
# the final image needs nothing but the binary itself and a place to keep
# the SQLite database file.
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /portal .

FROM alpine:3.20
RUN adduser -D -u 10001 portal
COPY --from=builder /portal /usr/local/bin/portal
RUN mkdir /data && chown portal:portal /data
USER portal
VOLUME ["/data"]
ENV PORTAL_DB_PATH=/data/portal.db
EXPOSE 8090
ENTRYPOINT ["portal", "--addr", ":8090"]
