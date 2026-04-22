# True positive #1 — FROM with no tag (defaults to :latest)
FROM node
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "server.js"]
