# Build the Go recorder, then run it as a non-root user on a minimal base.
# Build context is the repo root (set in main.tf) so COPY can reach recorder/.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY recorder/ ./recorder/
RUN cd recorder && CGO_ENABLED=0 go build -trimpath -o /out/recorder .

FROM alpine:3.20
RUN adduser -D -u 10001 recorder \
    && mkdir -p /watch /ledger \
    && chown -R recorder:recorder /watch /ledger
COPY --from=build /out/recorder /usr/local/bin/recorder
USER recorder
ENTRYPOINT ["/usr/local/bin/recorder"]
