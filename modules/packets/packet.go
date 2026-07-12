package packets

import (
	serialize "github.com/mas-bandwidth/goserialize"
)

type Packet interface {
	Serialize(stream serialize.Stream) error
}

func WritePacket[P Packet](packetData []byte, packetObject P) ([]byte, error) {
	writeStream := serialize.NewWriteStream(packetData)
	err := packetObject.Serialize(writeStream)
	writeStream.Flush()
	return packetData[:int(writeStream.BytesProcessed())], err
}

func ReadPacket[P Packet](packetData []byte, packetObject P) error {
	readStream := serialize.NewReadStream(packetData)
	return packetObject.Serialize(readStream)
}
