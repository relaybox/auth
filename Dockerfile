# Stage 1: Build stage
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install --verbose
RUN npm install -g serverless
COPY ./src ./src
COPY ./functions ./functions
COPY tsconfig.json ./
COPY ./serverless.offline.yml ./serverless.offline.yml

# Stage 2: Production stage
FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app /app
RUN npm install -g serverless
EXPOSE 4005
CMD ["serverless", "offline", "start", "-c", "serverless.offline.yml", "--host", "0.0.0.0"]
