package main

type cliHandshake struct {
	versionID     byte
	methodsNumber byte
	methodArr     []byte
}

func makeCliHandshake(barr []byte) cliHandshake {
	var tmpv cliHandshake
	tmpv.versionID = barr[0]
	tmpv.methodsNumber = barr[1]
	tmpv.methodArr = barr[2:]
	return tmpv
}

type returnCliHandshake struct {
	versionID byte
	methodID  byte
}

func (rhs *returnCliHandshake) toByteArr() []byte {
	barr := make([]byte, 2)
	barr[0] = rhs.versionID
	barr[1] = rhs.methodID
	return barr
}

type cliRequest struct {
	versionID       byte
	commandID       byte
	reservedV       byte
	addrType        byte
	destinationAddr []byte
	destinationPort []byte
}

const (
	CMD_CONNECT = iota + 1
	CMD_BIND
	CMD_UDPASSOC
)

const (
	ADDR_IPV4 = iota + 1
	ADDR_RESV
	ADDR_DOM
	ADDR_IPV6
)

func makeCliRequest(barr []byte) cliRequest {
	var cltmp cliRequest
	cltmp.versionID = barr[0]
	cltmp.commandID = barr[1]
	cltmp.reservedV = barr[2]
	cltmp.addrType = barr[3]
	switch cltmp.addrType {
	case ADDR_IPV4:
		cltmp.destinationAddr = barr[4:8]
		cltmp.destinationPort = barr[8:10]
	case ADDR_DOM:
		domlen := barr[4]
		cltmp.destinationAddr = barr[5 : 5+domlen]
		cltmp.destinationPort = barr[5+domlen : 5+domlen+2]
	case ADDR_IPV6:
		cltmp.destinationAddr = barr[4:20]
		cltmp.destinationPort = barr[20:22]
	}
	return cltmp
}

type cliReply struct {
	versionID byte
	replyID   byte
	reservedV byte
	addrType  byte
	bindAddr  []byte
	bindPort  []byte
}

func (cr *cliReply) toByteArr() []byte {
	barr := make([]byte, 4)
	barr[0] = cr.versionID
	barr[1] = cr.replyID
	barr[2] = cr.reservedV
	barr[3] = cr.addrType
	barr = iappender(barr, cr.bindAddr)
	barr = iappender(barr, cr.bindPort)
	return barr
}
