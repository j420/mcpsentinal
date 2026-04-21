FROM node:20-alpine
WORKDIR /app
COPY .npmrc /root/.npmrc
COPY package*.json ./
RUN npm ci
COPY . .
CMD ["node", "dist/index.js"]
