FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/rahmadafandi/valetkey/internal/version.Version=${VERSION}" -o /valetkey ./cmd/valetkey

# alpine rather than distroless so the HEALTHCHECK can use wget.
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /valetkey /valetkey
COPY --chmod=0444 catalog.json /
RUN mkdir /data && chown 65532:65532 /data
VOLUME /data
ENV TZ=UTC CATALOG_FILE=/catalog.json DATABASE_URL=sqlite:///data/valetkey.db
EXPOSE 8080
USER 65532:65532
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/valetkey"]
