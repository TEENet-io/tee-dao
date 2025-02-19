// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v3.6.1
// source: rpc/node_comm.proto

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
	NodeComm_RequestHandler_FullMethodName = "/rpc.NodeComm/RequestHandler"
)

// NodeCommClient is the client API for NodeComm service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type NodeCommClient interface {
	// Sends a request for handler
	RequestHandler(ctx context.Context, in *NodeMsg, opts ...grpc.CallOption) (*NodeReply, error)
}

type nodeCommClient struct {
	cc grpc.ClientConnInterface
}

func NewNodeCommClient(cc grpc.ClientConnInterface) NodeCommClient {
	return &nodeCommClient{cc}
}

func (c *nodeCommClient) RequestHandler(ctx context.Context, in *NodeMsg, opts ...grpc.CallOption) (*NodeReply, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(NodeReply)
	err := c.cc.Invoke(ctx, NodeComm_RequestHandler_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// NodeCommServer is the server API for NodeComm service.
// All implementations must embed UnimplementedNodeCommServer
// for forward compatibility.
type NodeCommServer interface {
	// Sends a request for handler
	RequestHandler(context.Context, *NodeMsg) (*NodeReply, error)
	mustEmbedUnimplementedNodeCommServer()
}

// UnimplementedNodeCommServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedNodeCommServer struct{}

func (UnimplementedNodeCommServer) RequestHandler(context.Context, *NodeMsg) (*NodeReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RequestHandler not implemented")
}
func (UnimplementedNodeCommServer) mustEmbedUnimplementedNodeCommServer() {}
func (UnimplementedNodeCommServer) testEmbeddedByValue()                  {}

// UnsafeNodeCommServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to NodeCommServer will
// result in compilation errors.
type UnsafeNodeCommServer interface {
	mustEmbedUnimplementedNodeCommServer()
}

func RegisterNodeCommServer(s grpc.ServiceRegistrar, srv NodeCommServer) {
	// If the following call pancis, it indicates UnimplementedNodeCommServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&NodeComm_ServiceDesc, srv)
}

func _NodeComm_RequestHandler_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(NodeMsg)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(NodeCommServer).RequestHandler(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: NodeComm_RequestHandler_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(NodeCommServer).RequestHandler(ctx, req.(*NodeMsg))
	}
	return interceptor(ctx, in, info, handler)
}

// NodeComm_ServiceDesc is the grpc.ServiceDesc for NodeComm service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var NodeComm_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "rpc.NodeComm",
	HandlerType: (*NodeCommServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "RequestHandler",
			Handler:    _NodeComm_RequestHandler_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "rpc/node_comm.proto",
}
