FROM node:20-alpine

# Set the working directory to /app
WORKDIR /app

# Copy package.json and package-lock.json to the /app directory
COPY package*.json ./

# Install dependencies
RUN npm install

# Install serverless globally
RUN npm install -g serverless

# Copy the src directory to /app/src
COPY ./src ./src

# Copy the functions directory to /app/functions
COPY ./functions ./functions

# Copy tsconfig.json to the /app directory
COPY tsconfig.json ./

COPY ./serverless.yml ./

# COPY ./.env ./

# Expose the port for serverless-offline
EXPOSE 4005

# Command to run serverless offline
CMD ["serverless", "offline", "start", "--host", "0.0.0.0"]
