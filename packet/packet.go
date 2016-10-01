/**
 * Reversing Space: Dominons 4 Network Analysis
 * Copyright (c) 2015-2016 A.W. Stanley.
 *
 * This software is provided 'as-is', without any express or implied warranty.
 * In no event will the authors be held liable for any damages arising from
 * the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 *   1. The origin of this software must not be misrepresented; you must
 *      not claim that you wrote the original software. If you use this
 *      software in a product, an acknowledgment in the product
 *      documentation would be appreciated but is not required.
 *
 *   2. Altered source versions must be plainly marked as such, and
 *      must not be misrepresented as being the original software.
 *
 *   3. This notice may not be removed or altered from any
 *      source distribution.
 *
**/

package packet

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"io"
)

// decompressPacket0x49 performs decompression for 0x49
func decompressPacket0x49(src []byte, length uint32) (dst []byte, err error) {
	return nil, newReadError("unable to create lzh reader; not yet implemented", nil)
}

// decompressPacket0x4A performs decompression for 0x4A
func decompressPacket0x4A(src []byte, length uint32) (dst []byte, err error) {
	var z io.Reader
	z = flate.NewReader(bytes.NewReader(src))
	if err != nil {
		return nil, newReadError("failed to allocate flate reader for packet decompression", err)
	}

	// well beyond absolute worst case
	out := make([]byte, length)
	n, err := z.Read(out)
	if err != nil {
		return nil, newReadError("failed to decompress flate data", err)
	}
	dst = out[0:n]
	return
}

// Packet describes a networked packet.
type Packet struct {

	// Type
	// Base value seems to be 0x65; probably bit values or an arbitrary point.
	// 0x65 - Ping/Pong (heartbeat type)
	// 0x66 - Other(?)
	PacketType uint8

	// SubType information
	// - Is this flag based?
	//
	// 0x00 means not used.
	// 0x48 - Uncompressed
	// 0x49 = Compressed (old format used by dom3? lzh based on notes?)
	// 0x4A - Compressed (flate)
	PacketSubType uint8

	// Data will contain decompressed data (regardless of subtype).
	// For heartbeat (ping/pong) it will be empty.
	Data []byte

	// DataType describes the type of data stored.
	// % 2 determines if it is to or from the server:
	//     where the number is odd it is client to server;
	//     but where it is even it is server to client.
	//
	// This is the first byte of uncompressed data, used to handle
	// the data type.
	DataType uint8
}

// LoadPacket loads a Packet from a given io.Reader
// This allows for both file and network.
func LoadPacket(reader io.Reader) (packet *Packet, err error) {

	packet = &Packet{}

	var n int

	// Allocate the headers storage
	header := make([]byte, 2)

	// Read the first byte
	n, err = reader.Read(header[0:1])
	if err != nil {
		return nil, newReadError("failed to read packet: header type", err)
	}
	if n != 1 {
		return nil, errors.New("failed to read initial header byte, timeout or other undisclosed error hit")
	}

	// We have the type
	packet.PacketType = uint8(header[0])

	// Ping/pong types are irrelevant (at least here)
	if packet.PacketType == 0x65 {
		// We're done
		return
	}

	// Read the second byte (subtype)
	n, err = reader.Read(header[1:2])
	if err != nil {
		return nil, newReadError("failed to read packet: header subtype", err)
	}
	if n != 1 {
		return nil, errors.New("failed to read initial header byte, timeout or other undisclosed error hit")
	}
	packet.PacketSubType = uint8(header[1])

	// Read the length
	var length uint32
	err = binary.Read(reader, binary.LittleEndian, &length)
	if err != nil {
		return nil, newReadError("failed to read packet: header length", err)
	}

	raw := make([]byte, length)
	n, err = reader.Read(raw)
	if err != nil {
		return nil, newReadError("failed to read packet: bad data read", err)
	}
	if n != int(length) {
		return nil, errors.New("failed to read initial packet data: length not met")
	}

	switch packet.PacketSubType {
	case 0x48: // Uncompressed
		packet.Data = raw
		break
	case 0x49: // lzh?
		packet.Data, err = decompressPacket0x49(raw, length)
		break
	case 0x4A: // flate
		packet.Data, err = decompressPacket0x4A(raw, length)
		break
	}
	return
}

// WritePacket puts the packet back on the stream using (similar?) rules to
// what Dominions uses.
func (p *Packet) WritePacket(writer io.Writer) (err error) {
	b := bytes.NewBuffer(nil)
	var n int
	if p.PacketType == 0x65 {
		b.WriteByte(byte(p.PacketType))
		_, err = writer.Write(b.Bytes())
		return
	}

	// Write the type
	b.WriteByte(p.PacketType)

	// Avoid anything hinky; below 12 bytes we'd have a problem compressing.
	if len(p.Data) < 12 {
		// Straight on the wire!
		b.WriteByte(0x48)
		binary.Write(b, binary.LittleEndian, len(p.Data))
		_, err = writer.Write(b.Bytes())
	} else {
		// flate is the only compression option for Dominions 4
		var zb bytes.Buffer
		var z *flate.Writer
		z, err = flate.NewWriter(&zb, 1)
		if err != nil {
			err = newWriteError("failed to create a flate writer, using non-flate", err)
			return
		}
		b.WriteByte(0x4A)
		n, err = z.Write(p.Data)
		if err != nil {
			err = newWriteError("failed to write packet data to the flate, this is fatal to the stream", err)
			return
		}
		err = binary.Write(b, binary.LittleEndian, uint32(n))
		if err != nil {
			err = newWriteError("failed to write packet length to stream, this is fatal to the stream", err)
			return
		}
		_, err = writer.Write(b.Bytes())
		if err != nil {
			err = newWriteError("failed to flate data to the stream; this is fatal to the stream", err)
		}
	}
	return
}
