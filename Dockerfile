FROM --platform=$BUILDPLATFORM golang:alpine AS builder

WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 go build -o /src/bin/tools-server ./cmd/server

FROM --platform=$BUILDPLATFORM alpine:latest

WORKDIR /app
ENV GOTRACEBACK=crash

COPY --from=builder /src/bin/tools-server /app/tools-server

EXPOSE 8080

CMD ["/app/tools-server"]
