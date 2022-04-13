package internal

const crc24Init uint32 = 0xB704CE
const crc24Poly uint32 = 0x1864CFB

func ComputeCRC24(data []byte) []byte {
	crc := crc24Init
	for _, b := range data {
		crc ^= uint32(b) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= crc24Poly
			}
		}
	}
	return []byte{byte(crc >> 16), byte(crc >> 8), byte(crc)}
}
