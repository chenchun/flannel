package option

import (
	"net"
	"reflect"
	"testing"
)

func TestShiftBytesLeft(t *testing.T) {
	a := []byte{0x01, 0x2f}
	shifted := ShiftBytesLeft(a, 1)
	if !reflect.DeepEqual(shifted, []byte{0x02, 0x5e}) {
		t.Fatal(shifted)
	}
	a = []byte{0x01, 0x2f}
	shifted = ShiftBytesLeft(a, 4)
	if !reflect.DeepEqual(shifted, []byte{0x12, 0xf0}) {
		t.Fatal(shifted)
	}
	a = []byte{0x01, 0x2f}
	shifted = ShiftBytesLeft(a, 5)
	if !reflect.DeepEqual(shifted, []byte{0x25, 0xe0}) {
		t.Fatal(shifted)
	}
	a = []byte{0x01, 0x2f}
	shifted = ShiftBytesLeft(a, 9)
	if !reflect.DeepEqual(shifted, []byte{0x5e}) {
		t.Fatal(shifted)
	}
	a = []byte{0x01, 0x2f}
	shifted = ShiftBytesLeft(a, 16)
	if !reflect.DeepEqual(shifted, []byte{}) {
		t.Fatal(shifted)
	}
}

func TestShiftBytesRight(t *testing.T) {
	a := []byte{0x01, 0x2f}
	shifted := ShiftBytesRight(a, 1)
	if !reflect.DeepEqual(shifted, []byte{0x00, 0x97}) {
		t.Fatal(shifted)
	}
	a = []byte{0x01, 0x2f}
	shifted = ShiftBytesRight(a, 4)
	if !reflect.DeepEqual(shifted, []byte{0x00, 0x12}) {
		t.Fatal(shifted)
	}
	a = []byte{0x01, 0x2f}
	shifted = ShiftBytesRight(a, 5)
	if !reflect.DeepEqual(shifted, []byte{0x00, 0x09}) {
		t.Fatal(shifted)
	}
	a = []byte{0x01, 0x2f}
	shifted = ShiftBytesRight(a, 8)
	if !reflect.DeepEqual(shifted, []byte{0x01}) {
		t.Fatal(shifted)
	}
	a = []byte{0x01, 0x2f}
	shifted = ShiftBytesRight(a, 9)
	if !reflect.DeepEqual(shifted, []byte{0x00}) {
		t.Fatal(shifted)
	}
	a = []byte{0x01, 0x2f}
	shifted = ShiftBytesRight(a, 16)
	if !reflect.DeepEqual(shifted, []byte{}) {
		t.Fatal(shifted)
	}
}

func cidr(str string) *net.IPNet {
	ip, subnet, err := net.ParseCIDR(str)
	if err != nil {
		return nil
	}
	subnet.IP = ip
	return subnet
}

func TestEncodeOptionData(t *testing.T) {
	data := New(cidr("192.168.0.1/24")).EncodeOptionData(net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.2"))
	// 0b 11000  0000 0001  0000 0010
	// 0b 1100 0000 0000 1000 0001 0
	if !reflect.DeepEqual(data, []byte{0xc0, 0x08, 0x10}) {
		t.Fatal(data)
	}

	data = New(cidr("192.168.0.1/16")).EncodeOptionData(net.ParseIP("192.168.1.1"), net.ParseIP("192.168.2.2"))
	// 0b 10000  0000 0001 0000 0001  0000 0010 0000 0010
	// 0b 1000 0000 0000 1000 0000 1000 0001 0000 0001 0
	if !reflect.DeepEqual(data, []byte{0x80, 0x08, 0x08, 0x10, 0x10}) {
		t.Fatal(data)
	}

	data = New(cidr("192.168.192.0/18")).EncodeOptionData(net.ParseIP("192.168.193.2"), net.ParseIP("192.168.194.2"))
	// 0b 10010 00 0001 0000 0010 00 0010 0000 0010
	// 0b 1001 0000 0010 0000 0100 0001 0000 0001 0
	if !reflect.DeepEqual(data, []byte{0x90, 0x20, 0x41, 0x01, 0x00}) {
		t.Fatal(data)
	}
}

func TestDecodeOptionData(t *testing.T) {
	opt := New(&net.IPNet{IP: net.ParseIP("1.1.2.1"), Mask: net.CIDRMask(24, 32)})
	if err := opt.DecodeOptionData([]byte{0xc0, 0x08, 0x10}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opt, NewOption(net.CIDRMask(24, 32), net.ParseIP("1.1.2.1").To4(), net.ParseIP("1.1.2.2").To4())) {
		t.Fatal(opt)
	}

	opt = New(&net.IPNet{IP: net.ParseIP("1.3.0.0"), Mask: net.CIDRMask(16, 32)})
	if err := opt.DecodeOptionData([]byte{0x80, 0x08, 0x08, 0x10, 0x10}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opt, NewOption(net.CIDRMask(16, 32), net.ParseIP("1.3.1.1").To4(), net.ParseIP("1.3.2.2").To4())) {
		t.Fatal(opt)
	}

	if err := opt.DecodeOptionData([]byte{0x80, 0x08, 0x08, 0x10}); err == nil {
		t.Fatal("expect bad data, len is not correct")
	}

	//t.Log(hex.EncodeToString(EncodeOptionData(&Option{Mask: net.CIDRMask(18, 32), SrcIP: net.ParseIP("192.168.193.2"), DstIP: net.ParseIP("192.168.194.2")})))
	// ones=18, onesBits=10010, srcIP=192.168.193.2, srcIPSuffix=00 0001 0000 0010, dstIP=192.168.194.2, dstIPSuffix=00 0010 0000 0010
	// 10010 00 0001 0000 0010 00 0010 0000 0010
	// 1001 0000 0010 0000 0100 0001 0000 0001 0
	// prefixBits = 0xc0 0xa8 0xc0
	opt = New(&net.IPNet{IP: net.ParseIP("192.168.195.2"), Mask: net.CIDRMask(18, 32)})
	if err := opt.DecodeOptionData([]byte{0x90, 0x20, 0x41, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opt, NewOption(net.CIDRMask(18, 32), net.ParseIP("192.168.193.2").To4(), net.ParseIP("192.168.194.2").To4())) {
		t.Fatal(opt)
	}
}

func TestGenPrefixBits(t *testing.T) {
	ipNet := &net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.IPv4Mask(255, 255, 255, 0)}
	prefix := GenPrefixBits(ipNet)
	expect := []byte(ipNet.IP.To4())[:3]
	if !reflect.DeepEqual(prefix, expect) {
		t.Fatal(prefix)
	}

	ipNet = &net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(18, 32)}
	prefix = GenPrefixBits(ipNet)
	expect = []byte(ipNet.IP.To4())[:3]
	if !reflect.DeepEqual(prefix, expect) {
		t.Fatal(prefix)
	}

	ipNet = &net.IPNet{IP: net.IPv4(192, 168, 0, 1), Mask: net.CIDRMask(9, 32)}
	prefix = GenPrefixBits(ipNet)
	expect = []byte{192, 128}
	if !reflect.DeepEqual(prefix, expect) {
		t.Fatal(prefix)
	}
}
