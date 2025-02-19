// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.5
// 	protoc        v3.6.1
// source: rpc/node_comm.proto

package rpc

import (
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type NodeMsg struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	MsgType       uint32                 `protobuf:"varint,1,opt,name=msgType,proto3" json:"msgType,omitempty"`
	Data          []byte                 `protobuf:"bytes,2,opt,name=data,proto3" json:"data,omitempty"`
	From          string                 `protobuf:"bytes,3,opt,name=from,proto3" json:"from,omitempty"`
	To            string                 `protobuf:"bytes,4,opt,name=to,proto3" json:"to,omitempty"`
	CreateAt      *timestamp.Timestamp   `protobuf:"bytes,5,opt,name=createAt,proto3" json:"createAt,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *NodeMsg) Reset() {
	*x = NodeMsg{}
	mi := &file_rpc_node_comm_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *NodeMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NodeMsg) ProtoMessage() {}

func (x *NodeMsg) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_node_comm_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NodeMsg.ProtoReflect.Descriptor instead.
func (*NodeMsg) Descriptor() ([]byte, []int) {
	return file_rpc_node_comm_proto_rawDescGZIP(), []int{0}
}

func (x *NodeMsg) GetMsgType() uint32 {
	if x != nil {
		return x.MsgType
	}
	return 0
}

func (x *NodeMsg) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *NodeMsg) GetFrom() string {
	if x != nil {
		return x.From
	}
	return ""
}

func (x *NodeMsg) GetTo() string {
	if x != nil {
		return x.To
	}
	return ""
}

func (x *NodeMsg) GetCreateAt() *timestamp.Timestamp {
	if x != nil {
		return x.CreateAt
	}
	return nil
}

type NodeReply struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Success       bool                   `protobuf:"varint,1,opt,name=success,proto3" json:"success,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *NodeReply) Reset() {
	*x = NodeReply{}
	mi := &file_rpc_node_comm_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *NodeReply) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NodeReply) ProtoMessage() {}

func (x *NodeReply) ProtoReflect() protoreflect.Message {
	mi := &file_rpc_node_comm_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NodeReply.ProtoReflect.Descriptor instead.
func (*NodeReply) Descriptor() ([]byte, []int) {
	return file_rpc_node_comm_proto_rawDescGZIP(), []int{1}
}

func (x *NodeReply) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

var File_rpc_node_comm_proto protoreflect.FileDescriptor

var file_rpc_node_comm_proto_rawDesc = string([]byte{
	0x0a, 0x13, 0x72, 0x70, 0x63, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x03, 0x72, 0x70, 0x63, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x93, 0x01, 0x0a, 0x07,
	0x4e, 0x6f, 0x64, 0x65, 0x4d, 0x73, 0x67, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x73, 0x67, 0x54, 0x79,
	0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x6d, 0x73, 0x67, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x04, 0x64, 0x61, 0x74, 0x61, 0x12, 0x12, 0x0a, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x66, 0x72, 0x6f, 0x6d, 0x12, 0x0e, 0x0a, 0x02, 0x74, 0x6f, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x74, 0x6f, 0x12, 0x36, 0x0a, 0x08, 0x63, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x41, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x08, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41,
	0x74, 0x22, 0x25, 0x0a, 0x09, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x70, 0x6c, 0x79, 0x12, 0x18,
	0x0a, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x07, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x32, 0x3c, 0x0a, 0x08, 0x4e, 0x6f, 0x64, 0x65,
	0x43, 0x6f, 0x6d, 0x6d, 0x12, 0x30, 0x0a, 0x0e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48,
	0x61, 0x6e, 0x64, 0x6c, 0x65, 0x72, 0x12, 0x0c, 0x2e, 0x72, 0x70, 0x63, 0x2e, 0x4e, 0x6f, 0x64,
	0x65, 0x4d, 0x73, 0x67, 0x1a, 0x0e, 0x2e, 0x72, 0x70, 0x63, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x52,
	0x65, 0x70, 0x6c, 0x79, 0x22, 0x00, 0x42, 0x08, 0x5a, 0x06, 0x2e, 0x2e, 0x2f, 0x72, 0x70, 0x63,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
})

var (
	file_rpc_node_comm_proto_rawDescOnce sync.Once
	file_rpc_node_comm_proto_rawDescData []byte
)

func file_rpc_node_comm_proto_rawDescGZIP() []byte {
	file_rpc_node_comm_proto_rawDescOnce.Do(func() {
		file_rpc_node_comm_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_rpc_node_comm_proto_rawDesc), len(file_rpc_node_comm_proto_rawDesc)))
	})
	return file_rpc_node_comm_proto_rawDescData
}

var file_rpc_node_comm_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_rpc_node_comm_proto_goTypes = []any{
	(*NodeMsg)(nil),             // 0: rpc.NodeMsg
	(*NodeReply)(nil),           // 1: rpc.NodeReply
	(*timestamp.Timestamp)(nil), // 2: google.protobuf.Timestamp
}
var file_rpc_node_comm_proto_depIdxs = []int32{
	2, // 0: rpc.NodeMsg.createAt:type_name -> google.protobuf.Timestamp
	0, // 1: rpc.NodeComm.RequestHandler:input_type -> rpc.NodeMsg
	1, // 2: rpc.NodeComm.RequestHandler:output_type -> rpc.NodeReply
	2, // [2:3] is the sub-list for method output_type
	1, // [1:2] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_rpc_node_comm_proto_init() }
func file_rpc_node_comm_proto_init() {
	if File_rpc_node_comm_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_rpc_node_comm_proto_rawDesc), len(file_rpc_node_comm_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_rpc_node_comm_proto_goTypes,
		DependencyIndexes: file_rpc_node_comm_proto_depIdxs,
		MessageInfos:      file_rpc_node_comm_proto_msgTypes,
	}.Build()
	File_rpc_node_comm_proto = out.File
	file_rpc_node_comm_proto_goTypes = nil
	file_rpc_node_comm_proto_depIdxs = nil
}
