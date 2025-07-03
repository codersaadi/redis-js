# Project Overview

This project aims to create an open-source alternative to Upstash Redis, specifically focusing on a proxy server that is fully compatible with the existing Upstash Redis client library. The client library is designed to be edge-compatible and is currently used with a managed Upstash service.

## Goal

The primary goal is to ensure that the `apps/go-proxy` server adheres to the API contract of the `pkg/` (Upstash Redis client) library. This means the proxy server should correctly interpret and respond to requests made by the Upstash client, allowing the client's existing test suite to pass when pointed at our proxy.

## Key Compatibility Areas

- **Request/Response Format**: The proxy must handle the JSON request and response structures expected by the client, including single commands, pipelined commands, and multi-exec transactions.
- **Header Handling**: Specific headers like `upstash-sync-token` (for read-your-writes consistency) and `Upstash-Encoding` (for base64 encoding/decoding) must be correctly processed.
- **Command Semantics**: The proxy needs to accurately implement the behavior of various Redis commands as expected by the client, including special handling for commands like `EVAL`, `EVALSHA`, `MGET`, `MSET`, and `SET` with options.
- **Error Handling**: Errors returned by the proxy should match the format and content expected by the client.

## Verification Strategy

The compatibility will be verified by:

1.  Running the `apps/go-proxy` server locally.
2.  Configuring the `pkg/` client tests to connect to the local proxy server.
3.  Ensuring all relevant client tests pass, indicating successful API compatibility.

## Current Status

- `apps/go-proxy`: Go-based Redis proxy server with basic Redis command handling, authentication, metrics, and health checks.
- `pkg/`: Upstash Redis client library with various Redis command implementations, pipelining, and auto-pipelining features, along with a comprehensive test suite.

This `GEMINI.md` will be updated as the project progresses and new insights are gained during the compatibility work.
