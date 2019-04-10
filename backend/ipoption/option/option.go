package option

import (
	"fmt"
	"math"
	"net"
)

// http://www.rhyshaden.com/ipdgram.htm
// https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml
const IPOptionType uint8 = 40

// ONES         (32-$ONES)*2
// 5bits(0-31)  IP_SUFFIX1 IP_SUFFIX2
// subnet=24 5+8*2=21bits
const subnetBits = 5

type Option struct {
	Mask  net.IPMask
	SrcIP net.IP
	DstIP net.IP

	// for speed up encoding
	prefix    uint
	shiftBits uint

	// for speed up decoding
	prefixBits []byte
	numBytes   int
}

func NewOption(mask net.IPMask, src, dst net.IP) *Option {
	opt := New(&net.IPNet{IP: src, Mask: mask})
	copy(opt.SrcIP, src.To4())
	copy(opt.DstIP, dst.To4())
	return opt
}

func New(cidr *net.IPNet) *Option {
	ones, _ := cidr.Mask.Size()
	srcIP, dstIP, temp := make([]byte, 4), make([]byte, 4), make([]byte, 4)
	copy(temp, cidr.IP.To4())
	prefixBits := GenPrefixBits(&net.IPNet{IP: temp, Mask: cidr.Mask})
	copy(srcIP, prefixBits)
	copy(dstIP, prefixBits)
	return &Option{
		SrcIP:      srcIP,
		DstIP:      dstIP,
		Mask:       cidr.Mask,
		prefix:     uint(ones),
		shiftBits:  (32 - uint(ones) - 8 + subnetBits) % 8,
		prefixBits: prefixBits,
		numBytes:   int(math.Ceil(float64(subnetBits+(32-ones)*2) / 8)),
	}
}

// EncodeOptionData encodes two ips as bytes array
// input mask is always 0 <= <= 31
func (d *Option) EncodeOptionData(src, dst net.IP) []byte {
	b1 := byte(d.prefix) << 3
	// copy 3 high bits of ip1 to the low bits of b1
	suffix1 := ShiftBytesLeft(src.To4(), d.prefix)
	suffix2 := ShiftBytesLeft(dst.To4(), d.prefix)
	b1 = b1 | (suffix1[0] >> subnetBits)
	suffix1 = ShiftBytesLeft(suffix1, 8-subnetBits)
	suffix1[len(suffix1)-1] |= suffix2[0] >> d.shiftBits
	suffix2 = ShiftBytesLeft(suffix2, 8-d.shiftBits)
	return append(append([]byte{b1}, suffix1...), suffix2...)
}

func (d *Option) DecodeOptionData(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}
	if d.numBytes != len(data) {
		return fmt.Errorf("invalid data %v, expect %d bytes", data, d.numBytes)
	}
	// TODO don't make a new array
	temp := make([]byte, len(data)+9)
	copy(temp, data)
	// shift right ones bits
	temp = ShiftBytesRight(temp, 3)
	temp = temp[1:]
	temp = ShiftBytesRight(temp, d.prefix%8)
	ipBytes := int(math.Ceil(float64(32-d.prefix) / 8))
	for i := 4 - ipBytes; i < 4; i++ {
		d.SrcIP[i] |= temp[i-4+ipBytes]
	}
	temp = ShiftBytesRight(temp[ipBytes:], d.prefix%8)
	for i := 4 - ipBytes; i < 4; i++ {
		d.DstIP[i] |= temp[i-4+ipBytes]
	}
	return nil
}

// ShiftBytesLeft shift `a` left by `bits` bits and shrink the len of `a` accordingly
func ShiftBytesLeft(a []byte, bits uint) []byte {
	beginByte := int(bits / 8)
	bits = bits % 8
	if beginByte == len(a) {
		return []byte{}
	}
	a = a[beginByte:]
	for i := 0; i < len(a); i++ {
		a[i] <<= bits
		if i != len(a)-1 {
			a[i] |= (a[i+1] >> (8 - bits))
		}
	}
	return a
}

// ShiftBytesRight shift `a` right by `bits` bits and shrink the len of `a` accordingly
func ShiftBytesRight(a []byte, bits uint) []byte {
	endByte := len(a) - int(bits/8)
	bits = bits % 8
	if endByte <= 0 {
		return []byte{}
	}
	a = a[:endByte]
	for i := len(a) - 1; i >= 0; i-- {
		a[i] >>= bits
		if i != 0 {
			a[i] |= a[i-1] << (8 - bits)
		}
	}
	return a
}

func GenPrefixBits(ipNet *net.IPNet) []byte {
	ones, _ := ipNet.Mask.Size()
	return ipNet.IP.Mask(ipNet.Mask).To4()[:int(math.Ceil(float64(ones)/8))]
}
