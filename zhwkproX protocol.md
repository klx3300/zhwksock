# zhwkproX protocol

### handshake

step 1 : server to inter-server

(unit byte)

similar with socks5 proto handshake

for implementation convi

```
+----+----+----....
|vers|NuMe|SuppMeth
+----+----+----````
```

`vers` -- protocol version.for zhwkproX,it starts from `0x80`

`Nume` -- support auth method numbers. inherited from socks5 hs,in zhwkproX, constant `0x01`

`SuppMeth` -- array of supported method ids.inherited also,in zhwkproX,constant `0x00`



step 2 : inter-server reply

```
+----+
|vers|
+----+
```

`vers` -- protol version sent before



### auth

step 1 : server asks

```
+----+----....
|size|auth msg
+----+----````
```

`size` -- length of auth msg

`auth msg` -- authentication message



step 2 : interserver reply

```
+----+----....
|size|encr msg
+----+----````
```

`size` -- length of encrypted msg

`encr msg` -- encrypted version of auth msg sent before



details:

encryption methods and keys are hard-coded into software

server asks for the encryption version of auth msg from interserver,

the interserver will add some random bytes to the origin keys and re-encrypt it,

and decrypt it using itself commonIV and key string,

if the starting part are equal,then authentication process succeeded.



step 3 : server reply

```
+----+
|succ|
+----+
```

`succ` -- 0x00 failed.otherwise succeed.



### GET

step 1 : interserver request

```
+----+-----+----+--------+------------+
|ipvr|ipadd|port|dtlength|data        |
+----+-----+----+--------+------------+
```

`ipvr` -- the version of ip protocol following --- `0x04` indicates ipv4 and `0x06` indicates ipv6.

`ipaddr` -- the target ipaddress. ipv4 using 4 bytes with ipv6 using 16 bytes

`port` -- the target port. 2 bytes (tot 65,536 ports possibility).

`dtlength` -- the length of following data. 4 bytes length. encoded with `LITTLE-ENDIAN` . `NOT` network big.

`data` -- the data that need to transport to target server. encrypted using AES.



step 2 : server reply

```
+----+------+----+----+------------+
|ipvr|ipaddr|port|dlen|data        |
+----+------+----+----+------------+
```

the same with the interserver request.



details:

server will reuse the tcp connection between server and destination address.

if dlen equals 0, that means dst closed connection.