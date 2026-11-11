FROM golang:1.23 AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=dev

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/kelompok17 ./cmd/kelompok17

FROM gcr.io/distroless/static-debian12

COPY --from=build /out/kelompok17 /kelompok17

WORKDIR /work

USER 65532:65532

ENTRYPOINT [ "/kelompok17" ]