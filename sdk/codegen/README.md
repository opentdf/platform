# SDK Codegen

## Overview
This folder contains the code generation logic for the SDK's connectrpc components. It automates the creation of ConnectRPC wrapper clients to ensure consistency and reduce manual effort. These clients have similar interfaces to the GRPC proto generated clients allowing for ease of transition to ConnectRPC client-side.

---

## What It Generates
The code generation in this folder focuses on:
1. ConnectRPC wrapper clients for various platform services
2. Interfaces for each wrapper client

The clients generated are defined in `clientsToGenerateList` in `main.go`. 

---

## How to Run Code Generation
To generate the internal SDK code:

```bash
go run ./sdk/codegen
```

Or use the provided Makefile command
```bash
make connect-wrapper-generate
```