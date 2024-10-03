# Auth - RelayBox Authentication Service

RelayBox Auth is a serverless authentication service written in NodeJS, built to manage user authentication and access control to RelayBox realtime services and applications.

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

### Installation

Copy `.env.template` to `.env` and update the values as required. Once complete, install the dependencies with...

```
npm install
```

After installation is complete, start the application by running...

```
npm run dev
```

This will start the dev server on port `4005`.

## Local Development

We would recommend forking and cloning [relaybox-local](https://github.com/relaybox/relaybox-local) to assist with local development. It provides a local Docker environment for running RelayBox services and applications.

For local development we use `serverless-offline` to run the application locally and `vitest` for testing.

## Testing

Test files can be found at `./test`. These files include mocks and intergation tests. To manage local testing either amend `.env.test` to point at you local database or run a dedicated instance. Connection settings can be adjusted in `.env.test`.
