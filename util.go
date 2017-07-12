package main

// convert the ipaddrs that represents ipv4 address using ipv6
// formats to ipv4 address. otherwise will return unchanged.
func convipaddr624(in []byte) []byte {
	if len(in) != 16 {
		return in
	}
	// check is it can be correctly converted.
	correction := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF}
	for i := 0; i < len(correction); i++ {
		if in[i] != correction[i] {
			return in
		}
	}
	// truncate it into ipv4
	return in[12:16]
}
func iappender(a []byte, b []byte) []byte {
	for i := 0; i < len(b); i++ {
		a = append(a, b[i])
	}
	return a
}
func fullbarrcmp(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
