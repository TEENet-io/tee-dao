// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v3.12.4
// source: rpc/coordinator.proto

package rpc

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	Coordinator_GetConfig_FullMethodName = "/rpc.Coordinator/GetConfig"
)

// CoordinatorClient is the client API for Coordinator service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
//
// The signature service definition.
type CoordinatorClient interface {
	// Sends a get config
	GetConfig(ctx context.Context, in *GetConfigRequest, opts ...grpc.CallOption) (*GetConfigReply, error)
}

type coordinatorClient struct {
	cc grpc.ClientConnInterface
}

func NewCoordinatorClient(cc grpc.ClientConnInterface) CoordinatorClient {
	return &coordinatorClient{cc}
}

func (c *coordinatorClient) GetConfig(ctx context.Context, in *GetConfigRequest, opts ...grpc.CallOption) (*GetConfigReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetConfigReply)
	err := c.cc.Invoke(ctx, Coordinator_GetConfig_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CoordinatorServer is the server API for Coordinator service.
// All implementations must embed UnimplementedCoordinatorServer
// for forward compatibility.
//
// The signature service definition.
type CoordinatorServer interface {
	// Sends a get config
	GetConfig(context.Context, *GetConfigRequest) (*GetConfigReply, error)
	mustEmbedUnimplementedCoordinatorServer()
}

// UnimplementedCoordinatorServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedCoordinatorServer struct{}

func (UnimplementedCoordinatorServer) GetConfig(context.Context, *GetConfigRequest) (*GetConfigReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetConfig not implemented")
}
func (UnimplementedCoordinatorServer) mustEmbedUnimplementedCoordinatorServer() {}
func (UnimplementedCoordinatorServer) testEmbeddedByValue()                     {}

// UnsafeCoordinatorServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CoordinatorServer will
// result in compilation errors.
type UnsafeCoordinatorServer interface {
	mustEmbedUnimplementedCoordinatorServer()
}

func RegisterCoordinatorServer(s grpc.ServiceRegistrar, srv CoordinatorServer) {
	// If the following call pancis, it indicates UnimplementedCoordinatorServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&Coordinator_ServiceDesc, srv)
}

func _Coordinator_GetConfig_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetConfigRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CoordinatorServer).GetConfig(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Coordinator_GetConfig_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CoordinatorServer).GetConfig(ctx, req.(*GetConfigRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Coordinator_ServiceDesc is the grpc.ServiceDesc for Coordinator service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Coordinator_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "rpc.Coordinator",
	HandlerType: (*CoordinatorServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetConfig",
			Handler:    _Coordinator_GetConfig_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "rpc/coordinator.proto",
}