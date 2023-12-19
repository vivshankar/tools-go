FROM --platform=$BUILDPLATFORM golang:alpine as builder

RUN echo $BUILDPLATFORM

COPY . /src
RUN mkdir -p /src/.build && \
    ls -al /src/.build && \
    cd /src/.build && \
    go build -o /src/.build/tools-server github.com/vivshankar/tools-go/cmd/server

FROM --platform=$BUILDPLATFORM alpine

RUN echo $BUILDPLATFORM

WORKDIR /app

ENV GOTRACEBACK=crash

COPY --from=builder /src/.build/tools-server /app

EXPOSE 8080

CMD /app/tools-server
