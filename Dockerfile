FROM golang:1.26-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /agentshield ./cmd/agentshield

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /agentshield /usr/local/bin/agentshield
WORKDIR /workspace
ENTRYPOINT ["agentshield"]
