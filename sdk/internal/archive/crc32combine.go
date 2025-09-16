package archive

// CRC32CombineIEEE combines two CRC-32 (IEEE) checksums as if the data were concatenated.
// crc1 is the CRC of the first part, crc2 of the second part, and len2 is the byte length of the second part.
// This uses the standard reflected IEEE polynomial 0xEDB88320 as used by ZIP.
func CRC32CombineIEEE(crc1, crc2 uint32, len2 int64) uint32 {
	if len2 <= 0 {
		return crc1
	}

	var even [32]uint32
	var odd [32]uint32

	// Operator for one zero bit in 'odd'
	odd[0] = 0xEDB88320 // reflected IEEE polynomial
	row := uint32(1)
	for n := 1; n < 32; n++ {
		odd[n] = row
		row <<= 1
	}

	// even = odd^(2), odd = even^(2)
	gf2MatrixSquare(even[:], odd[:])
	gf2MatrixSquare(odd[:], even[:])

	// Apply len2 zero bytes to crc1
	for {
		gf2MatrixSquare(even[:], odd[:])
		if (len2 & 1) != 0 {
			crc1 = gf2MatrixTimes(even[:], crc1)
		}
		len2 >>= 1
		if len2 == 0 {
			break
		}
		gf2MatrixSquare(odd[:], even[:])
		if (len2 & 1) != 0 {
			crc1 = gf2MatrixTimes(odd[:], crc1)
		}
		len2 >>= 1
		if len2 == 0 {
			break
		}
	}

	return crc1 ^ crc2
}

func gf2MatrixTimes(mat []uint32, vec uint32) uint32 {
	var sum uint32
	i := 0
	for vec != 0 {
		if (vec & 1) != 0 {
			sum ^= mat[i]
		}
		vec >>= 1
		i++
	}
	return sum
}

func gf2MatrixSquare(square, mat []uint32) {
	for n := 0; n < 32; n++ {
		square[n] = gf2MatrixTimes(mat, mat[n])
	}
}
