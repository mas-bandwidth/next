package encoding

import (
	"encoding/binary"
	"net"

	serialize "github.com/mas-bandwidth/serialize.go"
)

// SerializeAddress serializes a UDP address over a serialize.go stream. serialize.go is the
// general-purpose bitpacking library (a Go port of the canonical C++ serialize lib) and
// deliberately has no address method; this is the one SDK-specific serialize helper, the
// exact analog of serialize_address in the C++ SDK. It is a free function over the
// serialize.Stream interface, not a wrapper type.
//
// Wire format (matches the pre-serialize.go encoding and the C++ SDK): a 2-bit address
// type (none/ipv4/ipv6), then for ipv4 the 4 address bytes (byte aligned) and a 16-bit
// port. The system is IPv4-only; the ipv6 branch is kept for completeness.
func SerializeAddress(stream serialize.Stream, addr *net.UDPAddr) error {

	var addrType uint32
	if stream.IsWriting() {
		if addr.IP == nil {
			addrType = IPAddressNone
		} else if addr.IP.To4() == nil {
			addrType = IPAddressIPv6
		} else {
			addrType = IPAddressIPv4
		}
	}

	stream.SerializeBits(&addrType, 2)
	if stream.Err() != nil {
		return stream.Err()
	}

	switch addrType {

	case IPAddressIPv4:
		if stream.IsReading() {
			addr.IP = make([]byte, 16)
			addr.IP[10] = 255
			addr.IP[11] = 255
		}
		stream.SerializeBytes(addr.IP[12:16])
		var port uint32
		if stream.IsWriting() {
			port = uint32(addr.Port)
		}
		stream.SerializeBits(&port, 16)
		if stream.IsReading() {
			addr.Port = int(port)
		}

	case IPAddressIPv6:
		if stream.IsReading() {
			addr.IP = make([]byte, 16)
		}
		for i := 0; i < 8; i++ {
			var v uint32
			if stream.IsWriting() {
				v = uint32(binary.BigEndian.Uint16(addr.IP[i*2:]))
			}
			stream.SerializeBits(&v, 16)
			if stream.IsReading() {
				binary.BigEndian.PutUint16(addr.IP[i*2:], uint16(v))
			}
		}
		var port uint32
		if stream.IsWriting() {
			port = uint32(addr.Port)
		}
		stream.SerializeBits(&port, 16)
		if stream.IsReading() {
			addr.Port = int(port)
		}

	default:
		if stream.IsReading() {
			*addr = net.UDPAddr{}
		}
	}

	return stream.Err()
}
