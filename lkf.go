package lkf

const (
	blockSize        = 128 // The block size in words. Each word is uint32
	BlockSizeInBytes = blockSize * 4
	delta            = 0x9e3779b9
)

// The 128-bit key for encrypting/decrypting lkf files. It is divided into 4 parts of 32 bit each.
var key = [4]uint32{
	0x8ac14c27,
	0x42845ac1,
	0x136506bb,
	0x05d47c66,
}

func calcKey(leftWord, rightWord, r, k uint32) uint32 {
	n := (leftWord>>5 ^ rightWord<<2) + (rightWord>>3 ^ leftWord<<4)
	n ^= (key[(r>>2^k)&3] ^ leftWord) + (r ^ rightWord)
	return n
}

// A Cryptor represents internal buffer, used for encrypting/decrypting passed data.
type Cryptor struct {
	block [blockSize]uint32
}

func (c *Cryptor) toBlock(data []byte) {
	for i := range c.block {
		b := data[4*i:]
		c.block[i] = uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	}
}

func (c *Cryptor) fromBlock(data []byte) {
	for i, v := range c.block {
		b := data[4*i:]
		b[0] = byte(v)
		b[1] = byte(v >> 8)
		b[2] = byte(v >> 16)
		b[3] = byte(v >> 24)
	}
}

// Encrypt encrypts first len(data) / BlockSizeInBytes blocks. Returns the size all encrypted blocks. If len(data) < BlockSizeInBytes - returns 0.
func (c *Cryptor) Encrypt(data []byte) int {
	nBlocks := len(data) / BlockSizeInBytes
	for i := 0; i < nBlocks; i++ {
		b := data[i*BlockSizeInBytes:]
		c.toBlock(b)
		// Used only 3 rounds
		for r := uint32(1); r <= 3; r++ {
			var x uint32 = r * delta
			lWord := c.block[blockSize-1]
			for k := 0; k < blockSize-1; k++ {
				c.block[k] += calcKey(lWord, c.block[k+1], x, uint32(k))
				lWord = c.block[k]
			}
			c.block[blockSize-1] += calcKey(lWord, c.block[0], x, uint32(blockSize-1))
		}
		c.fromBlock(b)
	}
	return nBlocks * BlockSizeInBytes
}

// Decrypt decrypts first len(data) / BlockSizeInBytes blocks. Returns the size all decrypted blocks. If len(data) < BlockSizeInBytes - returns 0.
func (c *Cryptor) Decrypt(data []byte) int {
	nBlocks := len(data) / BlockSizeInBytes
	for i := 0; i < nBlocks; i++ {
		b := data[i*BlockSizeInBytes:]
		c.toBlock(b)
		// Used only 3 rounds
		for r := uint32(3); r != 0; r-- {
			var x uint32 = r * delta
			rWord := c.block[0]
			for k := blockSize - 1; k > 0; k-- {
				c.block[k] -= calcKey(c.block[k-1], rWord, x, uint32(k))
				rWord = c.block[k]
			}
			c.block[0] -= calcKey(c.block[blockSize-1], rWord, x, uint32(0))
		}
		c.fromBlock(b)
	}
	return nBlocks * BlockSizeInBytes
}
