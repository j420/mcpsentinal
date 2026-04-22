FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
# BuildKit secret mount — the .npmrc content is available during this RUN only,
# it is NEVER copied into an image layer. The rule should not fire.
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci
COPY . .
CMD ["node", "dist/index.js"]
