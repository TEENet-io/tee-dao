# grpc
The initialization of `grpcServer` is realized in `comm/server.go/NewServer()`, it load the cert and keys, create a new `grpcServer` and put it in the Server.

The `ListenRPC()` just create a listener and make the server start to serve the rpc.

## How to create a new service

1. Create a proto file for the service, then compile with `protoc`. (refer to `rpc/signature.proto`)

2. Implement the service. (refer to `frost_dkg_multisig/signature_service_grpc.go`)

3. Add register for the service: In `comm/server.go/RegisterRPC()`

4. The client side code of calling the rpc also need modification
