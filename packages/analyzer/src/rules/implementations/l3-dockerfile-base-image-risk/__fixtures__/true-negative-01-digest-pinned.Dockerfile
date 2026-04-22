# True negative #1 — fully digest-pinned base image.
FROM alpine:3.18@sha256:0b3c98f3e41e0c94a2b8d6b47c2c4a1f9c6d4e5b8a7b2c1d3f9e8a7b6c5d4e3f
WORKDIR /srv
COPY --chown=nobody:nogroup . .
USER nobody
CMD ["./server"]
