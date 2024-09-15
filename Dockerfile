FROM node:20-alpine
WORKDIR /src
COPY package*.json ./
RUN npm install
COPY . .
RUN npm install -g serverless
EXPOSE 4005
CMD ["serverless", "offline", "start", "--host", "0.0.0.0"]