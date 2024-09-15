FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install
RUN npm install -g serverless

COPY ./src ./src
COPY ./functions ./functions
COPY tsconfig.json ./
COPY ./serverless.yml ./

EXPOSE 4005

CMD ["serverless", "offline", "start", "--host", "0.0.0.0"]
