# Stage 1: Build stage
FROM node:20-alpine AS builder

WORKDIR /app

COPY package.offline.json ./package.json
RUN npm install --verbose

COPY ./src ./src
COPY ./functions ./functions
COPY ./tsconfig.json ./
COPY ./serverless.offline.yml ./

# Stage 2: Production stage
FROM node:20-alpine

WORKDIR /app

ENV NODE_ENV=production
ENV TZ=UTC

COPY --from=builder /app /app

EXPOSE 4005

CMD ["npm", "start"]
