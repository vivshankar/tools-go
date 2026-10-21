FROM --platform=$BUILDPLATFORM golang:alpine AS builder

RUN echo $BUILDPLATFORM

COPY . /src

RUN mkdir -p /src/bin && \
    ls -al /src/bin && \
    cd /src/bin && \
    go build -o /src/bin/tools-server github.com/vivshankar/tools-go/cmd/server

# Generate the OIDC client key next to the binary, so it is embedded in the image
RUN /src/bin/tools-server -generate-key

FROM --platform=$BUILDPLATFORM alpine:latest

WORKDIR /app

ENV GOTRACEBACK=crash

COPY --from=builder /src/bin/tools-server /app/tools-server
COPY --from=builder /src/bin/client.jwk /app/client.jwk

EXPOSE 8080

CMD ["/app/tools-server"]
