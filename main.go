package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

const (
	STATE_WAITING_HS = iota
	STATE_REQUEST
	STATE_GET
	STATE_INTERSRV_AUTH
	STATE_INTERSRV_AUTH_CONT
	STATE_INTERSRV_SMSG
)

func main() {
	//portstate := make([]bool, 10000)
	//portbegin := uint(49107)
	listenaddr := "127.0.0.1:1992"
	thisSrvAddr, _ := net.ResolveTCPAddr("tcp4", "127.0.0.1:1992")
	tcpaddr, _ := net.ResolveTCPAddr("tcp4", listenaddr)
	listener, _ := net.ListenTCP("tcp", tcpaddr)
	receivedSrv := false
	getReplyChan := make(chan zhwkGetReply, 5)
	var srvConn net.Conn
	defer listener.Close()
	for {
		conn, _ := listener.Accept()
		go func() {
			defer conn.Close()
			// construct stm
			srstate := STATE_WAITING_HS
			var dstaddr []byte
			var dstport []byte
			dstaddr = make([]byte, 4)
			dstaddr[0] = 0xFF
			dstport = make([]byte, 2)
			dstport[0] = 0xFF
			for {
				tx := make([]byte, 102400)
				recvlen, err := conn.Read(tx)
				if err != nil {
					break
				}
				tx = tx[:recvlen]
				fmt.Printf("(%d) %v\nStr:\n%v\n", srstate, tx, string(tx))
				switch srstate {
				case STATE_WAITING_HS:
					hsinfo := makeCliHandshake(tx)
					if hsinfo.versionID != 5 || hsinfo.methodsNumber < 1 || *(hsinfo.methodArr) != 0 {
						// there are still possiblities
						// that is zhwkproX proto msg sent from zhwkproX server
						if hsinfo.versionID == 0x80 {
							// zhwkproX hs
							btmp := make([]byte, 1)
							btmp[0] = 0x80
							_, err := conn.Write(btmp)
							if err != nil {
								fmt.Printf("Network error. Terminated.\n")
								break
							}
							srstate = STATE_INTERSRV_AUTH
							continue
						}
						fmt.Printf("Unsupported authentication method.Terminated.\n")
						// return a no acceptable messeage back
						var rex returnCliHandshake
						rex.versionID = 5
						rex.methodID = 0xFF
						conn.Write(rex.toByteArr())
						break
					}
					var retx returnCliHandshake
					retx.versionID = 5
					retx.methodID = 0
					_, err := conn.Write(retx.toByteArr())
					if err != nil {
						fmt.Printf("Network error.Terminated.\n")
						break
					}
					// progress stm
					srstate = STATE_REQUEST
				case STATE_REQUEST:
					// sending requests from clients
					cr := makeCliRequest(tx)
					// check supportment
					if cr.commandID != CMD_CONNECT || cr.addrType == ADDR_IPV6 || cr.versionID != 5 {
						fmt.Printf("Unsupported operation error.Terminated.\n")
						break
					}
					// perform operations
					// set dstaddr,dstport
					if cr.addrType == ADDR_DOM {
						ipresult, err := net.LookupIP(string(cr.destinationAddr))
						if err != nil {
							fmt.Printf("Name Resolution Error.Terminated.\n")
							break
						}
						// only take the first result
						dstaddr = ipresult[0]
					} else {
						dstaddr = cr.destinationAddr
					}
					// convert ?
					dstaddr = convipaddr624(dstaddr)
					dstport = cr.destinationPort
					var crep cliReply
					// iteration to find a good port
					/*var pi uint
					for pi = 0; pi < uint(len(portstate)); pi++ {
						if !portstate[pi] {
							portstate[pi] = true
						}
					}*/
					crep.bindPort = make([]byte, 2)
					binary.BigEndian.PutUint16(crep.bindPort, uint16(thisSrvAddr.Port))
					crep.bindAddr = thisSrvAddr.IP
					crep.versionID = 0x05
					crep.replyID = 0x00
					crep.reservedV = 0x00
					crep.addrType = ADDR_IPV4
					// run a goroutine to listen at this port
					/*go func() {
						// first construct a dummy struct
						laddr, _ := net.ResolveTCPAddr("tcp4", ":10000")
						laddr.Port = int(pi + portbegin)
						llistener, _ := net.ListenTCP("tcp4", laddr)
						lconn, _ := llistener.AcceptTCP()
						defer lconn.Close()
						llistener.Close()
						for {
							ltx := make([]byte, 1024)
							lrecvlen, err := lconn.Read(ltx)
							if err != nil {
								break
							}
							ltx = ltx[0:lrecvlen]
							fmt.Printf("%v\n", ltx)
						}
					}()*/
					// return the values to the client
					_, err := conn.Write(crep.toByteArr())
					if err != nil {
						fmt.Printf("Network Error.Terminated.\n")
						break
					}
					srstate = STATE_GET
				case STATE_GET:
					// first print some debug messeages
					fmt.Printf("Attempt GET %v port %v\n", dstaddr, dstport)
					if receivedSrv == false {
						fmt.Printf("Failed due to no server connected yet.Terminating..\n")
						break
					}
					// construct getrequest
					var gr zhwkGetRequest
					if len(dstaddr) == 16 {
						gr.ipversion = 0x06
					} else {
						gr.ipversion = 0x04
					}
					gr.ipaddr = dstaddr
					gr.port = dstport
					gr.datalength = uint32(len(tx))
					gr.data = AESEncrypt(tx)
					_, rerr := srvConn.Write(gr.toByteArr())
					if rerr != nil {
						fmt.Printf("Network error.Terminated.\n")
						break
					}
					// start a goroutine to read stuff from returns
					go func() {
					LABEL_RST:
						tmgr := <-getReplyChan
						// check matching
						if fullbarrcmp(tmgr.ipaddr, dstaddr) && fullbarrcmp(tmgr.port, dstport) {
							// that's exactly what i need!
							retx := AESDecrypt(tmgr.data)
							conn.Write(retx)
						} else {
							go func() { getReplyChan <- tmgr }()
							goto LABEL_RST
						}
					}()
				case STATE_INTERSRV_AUTH:
					// authenticate with zhwkproX srv
					auinfo := makeAuthMsg(tx)
					auinfo.msg = iappender(auinfo.msg, []byte("fake rand strings"))
					var aurep zhwkAuthReply
					// take the risk of making this stuff not overflow the byte range
					aurep.repsize = byte(len(auinfo.msg))
					aurep.encmsg = AESEncrypt(auinfo.msg)
					_, err := conn.Write(aurep.toByteArr())
					if err != nil {
						fmt.Printf("Network Error.Terminated.\n")
						break
					}
					srstate = STATE_INTERSRV_AUTH_CONT
				case STATE_INTERSRV_AUTH_CONT:
					// waiting authentication successive
					if tx[0] != 0 {
						srstate = STATE_INTERSRV_SMSG
						receivedSrv = true
						srvConn = conn
					} else {
						fmt.Printf("Authentication Error.Terminated.\n")
						break
					}
				case STATE_INTERSRV_SMSG:
					// in this state,read all zhwkGetReplies and put into a go channel
					gr := makeGetReply(tx)
					go func() {
						getReplyChan <- gr
					}()
				}
			}
		}()
	}
}
