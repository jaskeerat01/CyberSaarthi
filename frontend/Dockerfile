# syntax=docker/dockerfile:1
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine
WORKDIR /app
# Non-root runtime user (spec §17 — no root in containers)
RUN addgroup -g 10001 -S app && adduser -S -u 10001 -G app app
RUN npm install -g serve && npm cache clean --force
COPY --from=build --chown=app:app /app/dist ./dist
USER app
EXPOSE 5173
CMD ["serve", "-s", "dist", "-l", "5173"]
