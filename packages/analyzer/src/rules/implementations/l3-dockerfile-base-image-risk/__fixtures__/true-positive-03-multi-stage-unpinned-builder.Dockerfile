# True positive #3 — multi-stage with unpinned builder (lethal edge case #1)
# The runtime stage pins a digest, but the builder stage uses a mutable
# tag. The COPY --from=build below inherits any compromised tooling from
# the unpinned builder tag — that artifact then contaminates the
# otherwise-pinned runtime stage.
FROM node:latest AS build
WORKDIR /app
COPY package.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM gcr.io/distroless/nodejs20-debian12@sha256:0b5eaf8e2a8d2f3f5e1f7c8c0a9e6b4e3f2d1c0b9a8d7e6c5b4a3f2e1d0c9b8a AS runtime
COPY --from=build /app/dist /app
CMD ["/app/server.js"]
