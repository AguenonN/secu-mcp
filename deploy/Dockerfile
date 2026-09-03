# Build every lab and service binary. The MCP go-sdk requires Go >= 1.25.
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
# The synthetic lab (identity thesis)...
RUN CGO_ENABLED=0 go build -o /out/agent          ./cmd/agent \
 && CGO_ENABLED=0 go build -o /out/network-config ./cmd/network-config \
 && CGO_ENABLED=0 go build -o /out/rogue          ./cmd/rogue \
# ...and the SRE service the same locks are carried into.
 && CGO_ENABLED=0 go build -o /out/mcp-observability ./cmd/mcp-observability \
 && CGO_ENABLED=0 go build -o /out/agent-sre         ./cmd/agent-sre \
 && CGO_ENABLED=0 go build -o /out/checkout-api      ./cmd/checkout-api

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/ /usr/local/bin/
COPY labdata /labdata
# Which binary runs is chosen per-service in docker-compose via `command:`.
