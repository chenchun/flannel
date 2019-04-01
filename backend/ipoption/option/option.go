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
}

func NewOption(mask net.IPMask, src, dst net.IP) *Option {
	srcIP, dstIP := make([]byte, 4), make([]byte, 4)
	copy(srcIP, src.To4())
	copy(dstIP, dst.To4())
	return &Option{Mask: mask, SrcIP: srcIP, DstIP: dstIP}
}

// EncodeOptionData encodes two ips as bytes array
// input mask is always 0 <= <= 31
func EncodeOptionData(d *Option) []byte {
	ones, _ := d.Mask.Size()
	b1 := byte(ones) << 3
	// copy 3 high bits of ip1 to the low bits of b1
	suffix1 := ShiftBytesLeft(d.SrcIP.To4(), uint(ones))
	suffix2 := ShiftBytesLeft(d.DstIP.To4(), uint(ones))
	b1 = b1 | (suffix1[0] >> subnetBits)
	suffix1 = ShiftBytesLeft(suffix1, 8-subnetBits)
	shiftBits := (32 - uint(ones) - 8 + subnetBits) % 8
	suffix1[len(suffix1)-1] |= suffix2[0] >> shiftBits
	suffix2 = ShiftBytesLeft(suffix2, 8-shiftBits)
	return append(append([]byte{b1}, suffix1...), suffix2...)
}

func DecodeOptionData(data, prefixBits []byte) (*Option, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	ones := int(data[0] >> (8 - subnetBits))
	numBytes := int(math.Ceil(float64(subnetBits+(32-ones)*2) / 8))
	if numBytes != len(data) {
		return nil, fmt.Errorf("invalid data %v, expect %d bytes", data, numBytes)
	}
	opt := &Option{Mask: net.CIDRMask(ones, 32)}
	ip1, ip2, temp := make([]byte, 4), make([]byte, 4), make([]byte, len(data))
	copy(ip1, prefixBits)
	copy(ip2, prefixBits)
	copy(temp, data)
	// shift right ones bits
	temp = append(temp, make([]byte, 9)...)
	temp = ShiftBytesRight(temp, 3)
	temp = temp[1:]
	temp = ShiftBytesRight(temp, uint(ones%8))
	ipBytes := int(math.Ceil(float64(32-ones) / 8))
	for i := 4 - ipBytes; i < 4; i++ {
		ip1[i] |= temp[i-4+ipBytes]
	}
	temp = ShiftBytesRight(temp[ipBytes:], uint(ones%8))
	for i := 4 - ipBytes; i < 4; i++ {
		ip2[i] |= temp[i-4+ipBytes]
	}
	opt.SrcIP, opt.DstIP = net.IP(ip1), net.IP(ip2)
	return opt, nil
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
