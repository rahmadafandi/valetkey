FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /valetkey ./cmd/valetkey

# alpine rather than distroless: platform health checks run wget inside the container.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /valetkey /valetkey
COPY catalog.json /
ENV TZ=UTC CATALOG_FILE=/catalog.json
EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/valetkey"]
