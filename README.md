# Auth - RelayBox Authentication Service

RelayBox Auth is a REST authentication service written in NodeJS, built to handle user authentication, session management and access control to RelayBox realtime services and applications.

View [@relaybox/client](https://relaybox.net/docs/api-reference/relaybox-client/auth) for more information about how client-side applications interact with this service. Think of this REST API as the backend for `relayBox.auth()`.

The auth service manages multiple processes including:

- Registration and verification
- User authentication
- Authorization
- Multi-factor authentication
- OAuth 2.0 authentication
- Session management
- Realtime services access control

## Getting Started

### Prerequisites

- Node.js 20.x
- Docker (optional)

### Installation

Copy `.env.template` to `.env` in the project root directory and update the values as required by your local environment. Once complete, install the dependencies with...

```
npm install
```

After installation is complete, start the application by running...

```
npm run dev
```

This will start the dev server on port `4005`. The default process manager is `nodemon` which works well with the chosen build and dev tools.

## Local Development

We'd recommend forking and/or cloning [relaybox-local](https://github.com/relaybox/relaybox-local) to assist with local development. It provides a local Docker environment for running RelayBox services including:

- Postgres
- Redis
- RabbitMQ

...and also runs nginx as a proxy service to manage path based routing for the system as a whole.

For local development we use `serverless-offline` with `esbuild` to run the application locally and `vitest` as a test runner.

## Testing

Test files can be found at `./test`. These files include mocks and intergation tests. To manage local testing configuration, either amend `.env.test` to point at your local database or run a dedicated instance.

## About the "Auth" service

The "auth" service is a group of Lambda functions that handle the entire authentication flow. From user registration and verification to authentication and session management. It also handles connection token verification from core realtime service. To learn more about `core`, head over to the [core repo](https://github.com/relaybox/core).

By leveraging strong cryptographic and security principles, this service can also be used as a standalone authentication service for any application that requires user authentication and session management.

Find out more about the service and it's features [here](https://relaybox.net/docs/authentication/live-auth)
