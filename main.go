package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
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
	listenaddr := ":1992"
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
			for {
				handleError := func(err error) bool {
					if err != nil {
						fmt.Printf("Error %v\n", err.Error())
						return true
					}
					return false
				}
				switch srstate {
				case STATE_WAITING_HS:
					var hsinfo cliHandshake
					tx := make([]byte, 2)
					_, err := conn.Read(tx)
					if handleError(err) {
						return
					}
					hsinfo.versionID = tx[0]
					hsinfo.methodsNumber = tx[1]
					tx = make([]byte, int(hsinfo.methodsNumber))
					_, err = conn.Read(tx)
					if handleError(err) {
						return
					}
					hsinfo.methodArr = tx
					if hsinfo.versionID != 5 || hsinfo.methodsNumber < 1 || hsinfo.methodArr[0] != 0 {
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
					_, err = conn.Write(retx.toByteArr())
					if err != nil {
						fmt.Printf("Network error.Terminated.\n")
						break
					}
					// progress stm
					srstate = STATE_REQUEST
				case STATE_REQUEST:
					// sending requests from clients
					var cr cliRequest
					tx := make([]byte, 4)
					_, err := conn.Read(tx)
					if handleError(err) {
						return
					}
					cr.versionID = tx[0]
					cr.commandID = tx[1]
					cr.reservedV = tx[2]
					cr.addrType = tx[3]
					switch cr.addrType {
					case ADDR_IPV4:
						cr.destinationAddr = make([]byte, 4)
						_, err = conn.Read(cr.destinationAddr)
						if handleError(err) {
							return
						}
					case ADDR_IPV6:
						cr.destinationAddr = make([]byte, 16)
						_, err = conn.Read(cr.destinationAddr)
						if handleError(err) {
							return
						}
					case ADDR_DOM:
						tx = make([]byte, 1)
						_, err = conn.Read(tx)
						if handleError(err) {
							return
						}
						cr.destinationAddr = make([]byte, int(tx[0]))
						_, err = conn.Read(cr.destinationAddr)
						if handleError(err) {
							return
						}
					}
					cr.destinationPort = make([]byte, 2)
					_, err = conn.Read(cr.destinationPort)
					if handleError(err) {
						return
					}
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
					_, err = conn.Write(crep.toByteArr())
					if err != nil {
						fmt.Printf("Network Error.Terminated.\n")
						break
					}
					go func(dstaddr []byte, dstport []byte) {
						// start a goroutine to read stuff from returns
						for {
							tmgr := <-getReplyChan
							// check matching
							if fullbarrcmp(tmgr.ipaddr, dstaddr) && fullbarrcmp(tmgr.port, dstport) {
								// that's exactly what i need!
								// check length:
								fmt.Printf("Received correct reply.\n")
								if tmgr.datalength == 0 {
									fmt.Printf("Connection Close Request Received.\n")
									conn.Close()
									return
								}
								retx := AESDecrypt(tmgr.data)
								fmt.Println(retx)
								fmt.Println(string(retx))
								conn.Write(retx)
							} else {
								go func() {
									time.Sleep(100 * time.Millisecond)
									getReplyChan <- tmgr
								}()
							}
						}
					}(dstaddr, dstport)
					srstate = STATE_GET
				case STATE_GET:
					// first print some debug messeages
					tx := make([]byte, 102400)
					n, err := conn.Read(tx)
					if handleError(err) {
						return
					}
					tx = tx[:n]
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
				case STATE_INTERSRV_AUTH:
					// authenticate with zhwkproX srv
					var auinfo zhwkAuthMsg
					tx := make([]byte, 1)
					_, err := conn.Read(tx)
					if handleError(err) {
						return
					}
					auinfo.msgsize = tx[0]
					tx = make([]byte, int(auinfo.msgsize))
					_, err = conn.Read(tx)
					if handleError(err) {
						return
					}
					auinfo.msg = tx
					auinfo.msg = iappender(auinfo.msg, []byte("fake rand strings"))
					var aurep zhwkAuthReply
					// take the risk of making this stuff not overflow the byte range
					aurep.repsize = byte(len(auinfo.msg))
					aurep.encmsg = AESEncrypt(auinfo.msg)
					fmt.Printf("Sending Authentication Messeage..\n")
					_, err = conn.Write(aurep.toByteArr())
					if err != nil {
						fmt.Printf("Network Error.Terminated.\n")
						break
					}
					srstate = STATE_INTERSRV_AUTH_CONT
				case STATE_INTERSRV_AUTH_CONT:
					// waiting authentication successive
					tx := make([]byte, 1)
					_, err := conn.Read(tx)
					if handleError(err) {
						return
					}
					if tx[0] != 0 {
						fmt.Printf("Authentication Succeed.\n")
						srstate = STATE_INTERSRV_SMSG
						receivedSrv = true
						srvConn = conn
					} else {
						fmt.Printf("Authentication Error.Terminated.\n")
						break
					}
				case STATE_INTERSRV_SMSG:
					// in this state,read all zhwkGetReplies and put into a go channel
					var gr zhwkGetReply
					tx := make([]byte, 1)
					_, err := conn.Read(tx)
					if handleError(err) {
						return
					}
					gr.ipversion = tx[0]
					var iplength int
					switch gr.ipversion {
					case 0x04:
						iplength = 4
					case 0x06:
						iplength = 16
					}
					tx = make([]byte, iplength)
					_, err = conn.Read(tx)
					if handleError(err) {
						return
					}
					gr.ipaddr = tx
					gr.port = make([]byte, 2)
					_, err = conn.Read(gr.port)
					if handleError(err) {
						return
					}
					tx = make([]byte, 4)
					_, err = conn.Read(tx)
					if handleError(err) {
						return
					}
					gr.datalength = binary.LittleEndian.Uint32(tx)
					gr.data = make([]byte, int(gr.datalength))
					_, err = conn.Read(gr.data)
					if handleError(err) {
						return
					}
					fmt.Printf("Received a reply from server.\n")
					go func(gr zhwkGetReply) {
						getReplyChan <- gr
						fmt.Printf("Reply sent to channel.\n")
					}(gr)
				}
			}
		}()
	}
}
