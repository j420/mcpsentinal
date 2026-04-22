# True negative #2 — scratch is Docker's built-in empty base; no supply-chain risk.
# Also demonstrates --platform flag stripping (charter lethal edge case #5).
FROM --platform=linux/amd64 golang:1.22@sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef AS build
WORKDIR /src
COPY . .
RUN go build -o /bin/server .

FROM scratch
COPY --from=build /bin/server /bin/server
ENTRYPOINT ["/bin/server"]
