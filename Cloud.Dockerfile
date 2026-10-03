FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /agentshield-cloud ./cmd/agentshield-cloud
RUN mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /agentshield-cloud /usr/local/bin/agentshield-cloud
COPY --from=build --chown=65532:65532 /data /data
VOLUME ["/data"]
ENV AGENTSHIELD_DATABASE=/data/agentshield-cloud.db
EXPOSE 8080
ENTRYPOINT ["agentshield-cloud"]
