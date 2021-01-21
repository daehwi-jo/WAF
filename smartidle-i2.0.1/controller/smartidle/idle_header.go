package smartidle

import (
	"bytes"
	"container/ring"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	//"charlie/i0.0.2/cls"
)

type Ips_s struct {
	sync.RWMutex

	//captcha bool // fqdn 별 접속 client 전체 captcha 동작

	IpsInfo IpsInfo_s
	//Wf      []WebFilter // web filter
}

type WebFilter struct {
	key   string // header key
	value string // header value
	wCase int    // case 1,2,3,4
	/*
			1 -> 포함 패스 / 미 포함 드랍
		    2 -> 포함 드랍 / 미 포함 패스
		    3 -> 크다 드랍 / 작다 패스
		    4 -> 크다 패스 / 작다 드랍
	*/

	//defUse     int // client 별 동작
	//captchaUse int // client 별 captcha 동작
}

type IpsInfo_s struct {
	conCnt *ring.Ring

	sname string

	id     int
	cnt    int
	period int
	except []string
	//expList string
	//cmd     []string
	cmdList string
	maxsize int
	filter  []string

	defUse     int
	captchaUse int

	plusonType string
	plusonIp   string
	plusonPort string

	Wf []WebFilter // web filter

	//	rtimerOn bool
	done chan bool
	//	gotcha   chan bool
	//	tcntOver chan RESULT
}

var FqdnMap = struct {
	sync.RWMutex
	m map[string]*Ips_s
}{m: make(map[string]*Ips_s)}

type HeaderInfo struct {
	cmd    string
	uri    string
	host   string
	cIp    string // client ip
	accept string
	reqUrl string // https://www.naver.com/....

	rbuf []byte

	clen int // content length
	hlen int // header length
	rlen int // read length

	forwardLen int //added length
}

var test_ips IpsInfo_s

func test_ring(fqdn string) IpsInfo_s {
	if test_ips.sname == "" {
		//		test_ips.ringflg = make(chan bool)
		test_ips.done = make(chan bool)
		//test_ips.gotcha = make(chan bool)
		//	test_ips.tcntOver = make(chan RESULT)
		test_ips.sname = fqdn
		test_ips.period = 10
		test_ips.cnt = 6
	}

	return test_ips
}

// tskim
func readHttpHeader(lcon net.Conn, bufsize, port int) (HeaderInfo, RESULT) { //rbuf, host
	var readLen, hlen, idx, i, s int
	var hInfo HeaderInfo
	//var setTimeOut bool

	var slowread bool

	lprintf(4, "[INFO] http read header \n")

	rbuf := make([]byte, bufsize)
	for {
		var rlen int
		var err error

		lprintf(4, "~~~~~~~~~~~~~~~~readLen(%d), bufsize(%d)~~~~~~~~~~~~", readLen, bufsize)

		if readLen >= bufsize {
			lprintf(4, "~~~~~~~~~~~~~~~~readLen(%d) over bufsize(%d)~~~~~~~~~~~~", readLen, bufsize)
			bufsize = bufsize + 1024
			newbuf := make([]byte, 1024)
			rbuf = append(rbuf, newbuf...)
		}

		//lprintf(4, "[INFO] aaaaaaaaa11")

		rlen, err = lcon.Read(rbuf[readLen:])
		//	lprintf(4, "rbuf(%s)", string(rbuf))
		if err != nil {
			lprintf(4, "[WARN] Http read failure or time out (%s)", err.Error())
			if slowread {
				// block client
				lprintf(1, "[ERROR] SLOW READ Notify BlackList Client (%s)", lcon.RemoteAddr().String())
				agent_noti(agent_make_wblist(BLACK, lcon.RemoteAddr().String(), "SLOWREAD", nil))
				//return hInfo, CLOSE
			}
			return hInfo, CLOSE
			/*if err, ok := err.(net.Error); setTimeOut && ok && err.Timeout() {
				if Slowread.ttl != 0 {
					if readLen > Slowread.size { // is reading
						lcon.SetReadDeadline(time.Time{})
						setTimeOut = false
						continue
					} else {
						// block client
						lprintf(4, "[AGENT] Notify BlackList Client (%s)", lcon.RemoteAddr().String())
						post_agent(make_json(BLACK, lcon.RemoteAddr().String()))
					}
				}
			}
			return hInfo, CLOSE*/
		}

		readLen = readLen + rlen
		//lprintf(4, "[INFO] aaaaaaaaa22")
		lprintf(4, "[INFO] header get(%s)readlen(%d),rlen(%d)", string(rbuf[:readLen]), readLen, rlen)
		// check slowread at first
		if Slowread.ttl != 0 {

			lprintf(4, "[INFO] slowread blocktime(%s), size(%d), ttl(%d) \n", Slowread.blocktime, Slowread.size, Slowread.ttl)

			if !slowread && readLen < Slowread.size {
				lcon.SetReadDeadline(time.Now().Add(time.Second * time.Duration(Slowread.ttl)))
				slowread = true
				continue
			}

			if slowread || readLen < Slowread.size {
				slowread = true
				continue
			}

			if slowread && readLen > Slowread.size {
				slowread = false
			}

			//pass only
			if !slowread && readLen > Slowread.size {
				//pass
			}

			/*
				if !setTimeOut && readLen < Slowread.size {
					lcon.SetReadDeadline(time.Now().Add(time.Second * time.Duration(Slowread.ttl)))
					setTimeOut = true
					continue
				}

				if setTimeOut && readLen > Slowread.size {
					lcon.SetReadDeadline(time.Time{})
					setTimeOut = false
				}*/

		}
		//lprintf(4, "[INFO] aaaaaaaaa33")
		if idx = bytes.Index(rbuf[:readLen], []byte("\r\n\r\n")); idx > 0 { // read header all
			hlen = idx + 4
			break
		}
	}

	//lprintf(4, "[INFO] read first http header(%s)", string(rbuf))

	var uIndex int
	// find  cmd, uri
	for i = 0; i < readLen; i++ {
		if rbuf[i] == ' ' {
			if s == 0 {
				hInfo.cmd = string(rbuf[:i])
				s = i + 1
			} else {
				hInfo.uri = string(rbuf[s:i])
				uIndex = s
			}
			continue
		}

		if rbuf[i] == '\r' {
			break
		}
	}

	// station으로 parking 요청 시 url에 구분값 parking 추가
	if Idle_t.MODE == 1 {

		rbuf = append([]byte("/parking/"), rbuf[uIndex+1:]...)
		rbuf = []byte(hInfo.cmd + " " + string(rbuf))
		readLen += 8

		hInfo.uri = "/parking" + hInfo.uri

		lprintf(4, "[INFO] http uri(%s) header(%s)\n ", hInfo.uri, string(rbuf))
	}

	//lprintf(4, "~~~~~~~~~~~~~~~~~~~~~rbuf(%s),readLen(%d)", rbuf, readLen)
	// host
	host, ret, _ := getHeaderValue(rbuf, "Host")
	if ret == -1 {
		lprintf(1, "[FAIL] header didnot have host")

		//if Idle_t.MODE == 0 {
		//details := "header didnot have host"
		//agent_sendErr(ERR_HOST_PKT, lcon.RemoteAddr().String(), "", strconv.Itoa(port), details)
		//}
		return hInfo, CLOSE
	}

	if tmp := strings.Split(host, ":"); len(tmp) > 0 {
		hInfo.host = tmp[0]
	} else {
		hInfo.host = host
	}

	lprintf(4, "[INFO] http header read host(%s) \n", hInfo.host)

	accept, _, _ := getHeaderValue(rbuf, "Accept")
	lprintf(4, "[INFO] accept(%s) \n", accept)
	hInfo.accept = accept

	/*idx = bytes.Index(rbuf[i:], []byte("Host: "))
	if idx > 0 {
		fin := bytes.Index(rbuf[idx:], []byte("\r\n"))
		lprintf(4, "")
		hInfo.host = string(rbuf[i+6 : fin])
	} else {
		lprintf(1, "[FAIL] header didnot have host")
		return hInfo, EXCPT
	}*/

	// Content-Length
	idx = bytes.Index(rbuf[i:], []byte("Content-Length: "))
	if idx > 0 {
		str, ret, _ := getHeaderValue(rbuf[idx:], "Content-Length")
		if ret == -1 {
			lprintf(1, "[FAIL] Header Content-Length naming wrong(%s)", string(rbuf[idx:idx+14]))

			//if Idle_t.MODE == 0 {
			//details := "Content-Length naming wrong - " + string(rbuf[idx:idx+14])
			//agent_sendErr(ERR_HOST_PKT, lcon.RemoteAddr().String(), hInfo.host, strconv.Itoa(port), details)
			//}
			return hInfo, CLOSE
		}
		clen, err := strconv.Atoi(str)
		if err != nil {
			lprintf(1, "[FAIL] Header content length is not number (%s)", str)

			//if Idle_t.MODE == 0 {
			//details := "content length is not number - " + str
			//agent_sendErr(ERR_HOST_PKT, lcon.RemoteAddr().String(), hInfo.host, strconv.Itoa(port), details)
			//}
			return hInfo, CLOSE
		}
		//lprintf(4, "clen(%d)", clen)
		/*fin := bytes.Index(rbuf[idx:], []byte("\r\n"))
		clen, err := strconv.Atoi(string(rbuf[idx+16 : fin]))
		if err != nil {
			lprintf(1, "[FAIL] header content length is not number (%s)", rbuf[idx+16:fin])
			return hInfo, EXCPT
		}*/
		hInfo.clen = clen
	}

	// delete forwarded info
	rst, newBuf, rmLen := delHeaderValue(rbuf, "X-Forwarded-For")
	if rst > 0 {
		copy(rbuf, newBuf)
		rbuf = rbuf[:len(rbuf)-rmLen]

		readLen = readLen - rmLen
		hlen = hlen - rmLen
	}

	// insert forwarded info
	ipcli := strings.Split(lcon.RemoteAddr().String(), ":")
	if len(ipcli) == 2 {
		forString := []byte("\r\nX-Forwarded-For: " + ipcli[0])
		flen := len(forString)
		hInfo.hlen = hlen + flen
		//hInfo.forwardLen = flen

		hInfo.cIp = ipcli[0]

		hInfo.rbuf = make([]byte, readLen+flen)
		hInfo.rlen = readLen + flen
		lprintf(4, "X-Forwarded-For:%s \n", ipcli[0])
		lprintf(4, "readLen(%d), flen(%d) \n", readLen, flen)
		lprintf(4, "readLen+flen(%d)////hlen-2(%d),hlen(%d),hlen+2(%d)", readLen+flen, hlen-2, hlen, hlen+2)
		copy(hInfo.rbuf[:hlen-4], rbuf[:hlen-4])
		copy(hInfo.rbuf[hlen-4:hlen-4+flen], forString[:flen])
		copy(hInfo.rbuf[hlen-4+flen:], rbuf[hlen-4:])

	} else {
		lprintf(1, "[FAIL] client did not have ip port (%s)", ipcli[0])
		return hInfo, CLOSE
	}

	// get Header
	return hInfo, PASS
}

func setRingcnt(ips *Ips_s) RESULT {

	//ips.RLock()
	//defer ips.RUnlock()

	ips.Lock()
	defer ips.Unlock()

	// increase counter
	if ips.IpsInfo.conCnt.Value == nil {
		//lprintf(1, "[ERROR] Ring goes something wrong.")
		return PASS
	}

	ips.IpsInfo.conCnt.Value = ips.IpsInfo.conCnt.Value.(int) + 1

	//check total count
	tmp := ips.IpsInfo.conCnt

	tcnt := 0
	for i := 0; i < tmp.Len(); i++ { // round trip
		tcnt += tmp.Value.(int)
		tmp = tmp.Next()
	}

	if tcnt > ips.IpsInfo.cnt {
		lprintf(1, "[ERROR] IPS request count is exceed tcnt(%d) (%s)", tcnt, ips.IpsInfo.sname)
		return CLOSE
	}

	return PASS
}

func createCounter(ips *Ips_s) {

	lprintf(4, "[INFO]  connection Counter check timer start (%d)sec", ips.IpsInfo.period)

	//	for i := 0; i < ips.IpsInfo.conCnt.Len(); i++ {
	//	ips.IpsInfo.conCnt.Value = 0
	//	ips.IpsInfo.conCnt = ips.IpsInfo.conCnt.Next()
	//}

	// call every 1 sec and reset connect counter
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {

		select {
		case <-ips.IpsInfo.done:
			return
		default:

		}

		ips.IpsInfo.conCnt = ips.IpsInfo.conCnt.Move(1)
		ips.IpsInfo.conCnt.Value = 0
	}

	return
}

/*func createCounter2(ipsinfo IpsInfo_s) {
	lprintf(4, "[INFO] connection Counter check timer start (%d)sec", ipsinfo.period)

	r := ring.New(ipsinfo.period) // 노드의 개수를 지정하여 링 생성

	for i := 0; i < r.Len(); i++ {
		r.Value = 0
		r = r.Next()
	}

	ticker := time.NewTicker(1 * time.Second)

	for range ticker.C {

		select {
		case <-ipsinfo.done:
			//ips rule changed or fqdn deleted
			lprintf(4, "[RING] timer closed. server name(%s)", ipsinfo.sname)
			return

		case <-ipsinfo.gotcha:
			r.Value = r.Value.(int) + 1
			lprintf(4, "[RING] cnt added (%d)", r.Value.(int))

			//add total cnts
			var tcnt int
			tmp := r
			for i := 0; i < r.Len(); i++ {
				tcnt += tmp.Value.(int)
				tmp = tmp.Next()
			}

			lprintf(4, "[RING] cnt total (%d)", tcnt)
			if tcnt > ipsinfo.cnt {
				//lprintf(4, "[IPSFILT] Server name(%s): Http max count over", ipsinfo.sname)
				ipsinfo.tcntOver <- CLOSE
			} else {

				ipsinfo.tcntOver <- PASS
			}

		default:

			//ipsinfo.tcntOver <- EXCPT

		}
		r = r.Move(1)
		r.Value = 0
	}
	return

}*/

/*func tpHttpRead(lcon net.Conn, bufsize int, reqinfo reqinfo_s) reqinfo_s { //rbuf, host

	//slow read filtered
	if reqinfo.ret == CLOSE {
		return reqinfo
	}

	var host string
	var ret int

	rbuf := make([]byte, bufsize)

	rlen, err := lcon.Read(rbuf)
	if err != nil {
		lprintf(1, "[FAIL] Http read failed(%s)", err)
		reqinfo.ret = RETURN
		return reqinfo
	}

	tmp := reqinfo.rbuf
	reqinfo.rbuf = reqinfo.rbuf + string(rbuf[:rlen])

	if reqinfo.ret == CONTENT {

		//	reqinfo.rbuf = reqinfo.rbuf + string(rbuf[:rlen])
		reqinfo.clen = reqinfo.clen - rlen

		return reqinfo
	}

	idx := bytes.Index(rbuf[:rlen], []byte("\r\n\r\n"))
	if idx != -1 {

		//this is header
		host, ret = getHeaderValue([]byte(reqinfo.rbuf), "Host")
		if ret == -1 {
			lprintf(4, "[FAIL] no host parsed")
			reqinfo.ret = RETURN
			return reqinfo
		}

		reqinfo.host = host

		FqdnMap.RLock()
		ipsinfo, exist := FqdnMap.m[host]
		FqdnMap.RUnlock()

		ipcli := strings.Split(lcon.RemoteAddr().String(), ":")
		if len(ipcli) == 2 {
			forString := fmt.Sprintf("\r\nX-Forwarded-For: %s", ipcli[0])
			reqinfo.rbuf = tmp + string(rbuf[:idx]) + forString + string(rbuf[idx:rlen])
			//rlen += len(forString)
		}

		if !exist {
			reqinfo.ret = PASS
			return reqinfo
		}

		if idx > ipsinfo.maxsize {
			lprintf(4, "[IPSFILT] Server name(%s): Over Maxsize", host)
			reqinfo.ret = CLOSE
			return reqinfo
		}

		reqinfo.ret, reqinfo.clen = header_check(string(rbuf[:idx]), len(reqinfo.rbuf), ipsinfo)
		if reqinfo.ret == EXCPT {
			if h_rmade(ipsinfo, lcon.RemoteAddr().String()) == false { //had already rtimer
				//	ipsinfo.ringflg <- true
			} else { //never had
				//ipsinfo.rtimerOn = true

				FqdnMap.Lock()
				FqdnMap.m[host] = ipsinfo
				FqdnMap.Unlock()
			}
			test_ring()
			if h_rmade(test_ips, lcon.RemoteAddr().String()) == false { //had already rtimer
				test_ips.ringflg <- true
			} else { //never had
				test_ips.rtimerOn = true

				FqdnMap.Lock()
				FqdnMap.m[host] = test_ips
				FqdnMap.Unlock()
			}
		}

		return reqinfo

	} else {
		if reqinfo.ret == LESS {
			reqinfo.host = "didn't get all"
			//reqinfo.rbuf = reqinfo.rbuf + string(rbuf[:rlen])
			return reqinfo
		}

		//reqinfo.rbuf = reqinfo.rbuf + string(rbuf[:rlen])
		//reqinfo.ret = PASS
	}

	reqinfo.ret = PASS
	return reqinfo

	//////////////////////////////////////////////////////////////

}

func header_check(header string, tlen int, ipsinfo IpsInfo) (RESULT, int) {
	var cmdflg bool
	var exflg int

	scanner := bufio.NewScanner(strings.NewReader(header))
	scanner.Split(bufio.ScanWords)
	for scanner.Scan() {
		word := scanner.Text()

		//CMD //first word
		if cmdflg == false {
			for _, val := range ipsinfo.cmd {
				if word == val {
					cmdflg = true
					break
				}
			}
			if cmdflg == true {
				continue
			} else {
				lprintf(4, "[IPSFILT] Server name(%s): Has another CMD(%s)", ipsinfo.sname, word)
				return CLOSE, 0
			}
		}

		//if has Content-Length
		if word == "Content-Length:" {
			scanner.Scan()
			clen, _ := strconv.Atoi(scanner.Text())
			hlen := len(header)
			if tlen-hlen < clen {
				return CONTENT, clen - tlen + hlen
			}
			return PASS, 0
		}

		//filter word
		for _, val := range ipsinfo.filter {
			if word == val {
				lprintf(4, "[IPSFILT] Server name(%s): Has Filter word", ipsinfo.sname)
				return CLOSE, 0
			}
		}

		if exflg < 2 {
			exflg++
			for _, val := range ipsinfo.except {
				if strings.Contains(word, val) {
					exflg = 3
					break
				}
			}
		}
	}
	if exflg != 3 {
		return EXCPT, 0
	}

	return PASS, 0
}

func htimer(slowread Slowread_s, done chan bool) {
	lprintf(4, "[INFO] header (slow read part) timer start ::: Time interval(%d)\n", slowread.ttl)

	//done <- false

	start := time.Now()
	ticker := time.NewTicker(1 * time.Second)

	for now := range ticker.C {

		d := int(now.Sub(start).Seconds())
		if d > slowread.ttl {
			lprintf(4, "[INFO] header timer(slow read part) expired, close the connection")
			done <- true //timer 종료 알리기
			return       // 만료된 타이머 종료
		}

		select {
		case <-done:
			lprintf(4, "[INFO] header (slow read part) passed, timer closed")
			return
		default:
			//lprintf(4, "timer on...")
		}
	}
}

//	r.Do(func(x interface{}) { // 링의 모든 노드 순회
//		fmt.Println(x)
//	})
func h_rtimer(ipsinfo IpsInfo, client_ip string) {
	lprintf(4, "[INFO] header (ring part) timer start (%d)sec", ipsinfo.period)

	r := ring.New(ipsinfo.period) // 노드의 개수를 지정하여 링 생성

	for i := 0; i < r.Len(); i++ {
		if i == 0 {
			r.Value = 1
		} else {
			r.Value = 0
		}
		r = r.Next()
	}

	//start := time.Now()
	ticker := time.NewTicker(1 * time.Second)

	for range ticker.C {

		//d := int(now.Sub(start).Seconds())
		select {
		case <-ipsinfo.done:
			//ips rule changed or fqdn deleted
			lprintf(4, "[RING] timer closed. server name(%s)", ipsinfo.sname)
			return

		case <-ipsinfo.gotcha:
			r.Value = r.Value.(int) + 1
			lprintf(4, "[RING] cnt added (%d)", r.Value.(int))

		default:
			//add total cnts
			var tcnt int
			for i := 0; i < r.Len(); i++ {
				tcnt += r.Value.(int)
				r = r.Next()
			}

			//lprintf(4, "[RING] cnt total (%d)", tcnt)

			if tcnt > ipsinfo.cnt {
				lprintf(4, "[IPSFILT] Server name(%s): Http max count over", ipsinfo.sname)

				//post agent
				post_agent(make_json(client_ip))
				return
			}

			r = r.Move(1)
			r.Value = 0
		}

	}

}


*/
