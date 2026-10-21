FROM --platform=$BUILDPLATFORM golang:alpine as builder

RUN echo $BUILDPLATFORM

COPY . /src
RUN mkdir -p /src/.build && \
    ls -al /src/.build && \
    cd /src/.build && \
    go build -o /src/.build/tools-server github.com/vivshankar/tools-go/cmd/server

# Generate the OIDC client key next to the binary, so it is embedded in the image
RUN /src/bin/tools-server -generate-key

FROM --platform=$BUILDPLATFORM alpine:latest

WORKDIR /app

ENV GOTRACEBACK=crash

COPY --from=builder /src/bin/tools-server /app/tools-server
COPY --from=builder /src/bin/client.jwk /app/client.jwk

EXPOSE 8080

CMD /app/tools-server
