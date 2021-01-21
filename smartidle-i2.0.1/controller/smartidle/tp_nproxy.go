package smartidle

import (
	//	"bytes"
	"container/ring"
	"crypto/tls"
	"fmt"
	"io"
	_ "math/rand"
	"net"

	//	"net/http"
	"strconv"
	"strings"

	"time"

	"charlie/i0.0.2/cls"
)

type ModuleInfo struct {
	sipsport [50]byte
	slen     uint32
	cipsport [50]byte
	clen     uint32
	sip      uint32
	cip      uint32
}

const (
	TP_HTTP = iota
	TP_TCP

	WRITE // idle write on client
	READ  // idle read from client

	IPS       // idle 통계 데이터
	WEBFILTER // idle 통계 데이터
)

// tcp, http basic proxy
func tpBasicProxy(pi ProxyInfo) {

	listen := fmt.Sprintf("%s:%d", cls.ListenIP, pi.lPort)
	lprintf(4, "[INFO] listen info(%s)", listen)

	if pi.protocol == HTTP_BLOCK {
		listener, err := net.Listen("tcp", listen)
		if err != nil {
			lprintf(1, "[FAIL] listen error (%s) ", err)
			return
		}
		defer listener.Close()

		for {
			conn, err := listener.Accept()
			if err != nil {
				lprintf(1, "[ERROR] tcp proxy accept error(%s)", err)
				continue
			}

			go tpHttpTarget3(conn, pi.tServer, pi.tPort)

		}

	} else {

		tcpAddr, err := net.ResolveTCPAddr("tcp", listen)
		if err != nil {
			lprintf(1, "[ERROR] ResolveTCPAddr(%s), error(%s) \n", listen, err.Error())
			return
		}

		listener, err := net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			lprintf(1, "[ERROR] ListenTCP(%), error(%s) \n", listen, err.Error())
			return
		}
		defer listener.Close()

		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				lprintf(1, "[ERROR] listener accept error(%s) \n", err.Error())
				continue
			}
			go tpTcpTarget2(conn, pi.tServer, pi.tPort)
		}

	}

}

func tpTcpProxy(portinfo BlockInfo) {

	port := portinfo.port
	block := portinfo.block

	listen := fmt.Sprintf("%s:%d", cls.ListenIP, port)
	target := fmt.Sprintf("%s:%d", Idle_t.TargetIP, port) // nginx mode

	/*
		if mode == 1 && block == HTTP_BLOCK { // parking mode
			hInfo := strings.Split(Idle_t.HttpProxy, ",")
			ip := strings.Split(hInfo[0], "&")
			ipIndex := rand.Intn(len(ip))                         // ipIndex = 0 ~ n
			target2 = fmt.Sprintf("%s:%d", ip[ipIndex], hInfo[1]) // parking mode

			lprintf(4, "[INFO] parking all ip(%s) \n", hInfo[0])
		}
	*/

	if portinfo.ssl == false {
		listener, err := net.Listen("tcp", listen)
		if err != nil {

			lprintf(1, "[FAIL] listen error (%s) ", err)

			if port == 80 || port == 443 || port == 1080 {
				return
			}

			//if mode == 0 {
			//details := "listen error - " + err.Error()
			//agent_sendErr(ERR_IDLE_LSN, "", "", strconv.Itoa(port), details)
			//}
			return
		}

		defer listener.Close()

		lprintf(4, "[LISTEN] LISTEN (%s)", listen)

		PortMap.Lock()
		PortMap.m[port] = portinfo
		PortMap.Unlock()

		for {

			// listen and accept
			conn, err := listener.Accept()
			if err != nil {
				//lprintf(1, "[FAIL] tcp proxy accept fail (%s)", err)
				//if mode == 0 {
				//details := "accept fail - " + err.Error()
				//agent_sendErr(ERR_IDLE_ACCT, "", "", strconv.Itoa(port), details)
				//}
				continue
			}
			lprintf(4, "[LISTEN] Accept client(%s) to server(%s)", conn.RemoteAddr().String(), listen)
			if block == HTTP_BLOCK {

				go tpHttpTarget2(conn, target, port, "http")

			} else if block == STREAM_BLOCK {
				go tpTcpTarget(conn, target, portinfo.domain, portinfo.fqdn, port)
			} else {
				lprintf(1, "[WARN] cannot find that port (%d) in the nginx config", port)

				//details := "cannot find that port in the nginx config"
				//agent_sendErr(ERR_PORT_NONE, conn.RemoteAddr().String(), "", strconv.Itoa(port), details)

				return
			}

		}

	} else {
		var flg int
		var cert tls.Certificate
		var listener net.Listener
		//var err error

		for {
			var err error
			lprintf(4, "[INFO] tls key file crt(%s), key(%s) \n", portinfo.crt, portinfo.key)
			cert, err = tls.LoadX509KeyPair(portinfo.crt, portinfo.key)
			if err != nil {
				if flg < 4 {
					flg++
					lprintf(1, "[ERROR] TLS config load (%s) Port (%d)", err.Error(), port)
					if strings.Contains(err.Error(), "PEM data") {
						lprintf(4, "[FAIL] Certification Downloading error, Check the Size of files.")
						return
					}
					//lprintf(4, "[INFO] CERT PATH (%s)", portinfo.crt)
				} else {
					lprintf(1, "[FAIL] Cannot find Cert (%s) Port (%d), Closed in 20 sec.", portinfo.crt, port)

					//details := "cannot find that Cert(" + portinfo.crt + ")or .key"
					//agent_sendErr(ERR_FILE_CERT, "", portinfo.fqdn, strconv.Itoa(port), details)

					return
				}
				time.Sleep(5 * time.Second)
				continue
			}
			lprintf(4, "[LISTEN] Loaded TLS Certification successfully.")

			break
		}

		//config := &tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
		config := &tls.Config{Certificates: []tls.Certificate{cert}}

		listener, err := tls.Listen("tcp", listen, config)
		if err != nil {
			lprintf(1, "[ERROR] TLS listen err (%s)", err.Error())

			//details := "listen error - " + err.Error()
			//agent_sendErr(ERR_IDLE_LSN, "", "", strconv.Itoa(port), details)

			return
		}
		defer listener.Close()

		lprintf(4, "[LISTEN] LISTEN TLS (%s)", listen)
		//go portChan(portinfo.close, port, listener)

		portinfo.ln_flg = true
		portinfo.ln = listener
		//portinfo.ssl = true

		PortMap.Lock()
		PortMap.m[port] = portinfo
		PortMap.Unlock()

		for {
			conn, err := listener.Accept()
			if err != nil {
				lprintf(1, "[ERROR] TLS accept err (%s)", err.Error())
				continue
			}
			lprintf(4, "[LISTEN] Accept TLS client (%s)", listen)

			if block == HTTP_BLOCK {
				go tpHttpTarget2(conn, target, port, "https")
			} else if block == STREAM_BLOCK {
				go tpTcpTarget(conn, target, portinfo.domain, portinfo.fqdn, port)
			} else {
				lprintf(1, "[WARN] cannot find that port (%d) in the nginx config", port)

				//details := "cannot find that port in the nginx config"
				//agent_sendErr(ERR_PORT_NONE, conn.RemoteAddr().String(), "", strconv.Itoa(port), details)

				return
			}

		}

	}

}

// nginx http
// tskim
////////////////////////////////////////////////////////////////////////////////////////////
func tpHttpTarget2(lcon net.Conn, taddr string, port int, protocol string) {

	lprintf(4, "[INFO] start http proxy read target ip(%s), port(%d)\n", taddr, port)

	hInfo, state := readHttpHeader(lcon, 1024, port)
	defer lcon.Close()
	if state != PASS {
		return
	}

	//cInfo := strings.Split(lcon.RemoteAddr().String(), ":")
	//clientIp := cInfo[0]

	myips := []string{"ipip.kr", "what-is-myip.net", "what-is-myip.org", "ip-servers.net", "ip-servers.org", "edge-ipconfig.com", "edge-ipconfig.net", "edge-findip.com", "edge-findip.net"}
	for i := 0; i < len(myips); i++ {
		if compare_domain(hInfo.host, myips[i]) {
			resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: idle\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", len(hInfo.cIp), hInfo.cIp)
			lcon.Write([]byte(resp))
			return
		}
	}

	if hInfo.uri == "/req_captcha" {
		page := "<!doctype html><html><head><script type=\"text/javascript\">"
		page += "function ClickRefresh() {"
		page += "document.getElementById(\"refresh\").value = \"1\";"
		page += "document.getElementById(\"frm\").submit();"
		page += "}</script><title>Captcha Test</title></head>"
		page += "<body>아래의 숫자를 순서대로 모두 입력해 주세요."
		page += "<form id=\"frm\" action=\"/ans_captcha\" method=\"post\">"
		page += "<img src=\"/req_captcha/image\"><br>"
		page += "<input type=\"text\" name=\"captchaInput\" maxlength=\"6\"><br>"
		page += "<input type=\"submit\" value=\"confirm\" >"
		page += "<input type=\"button\" value=\"refresh\" onclick=\"ClickRefresh();\"><br>"
		page += "<input type=\"hidden\" id=\"refresh\" name=\"refresh\" value=\"0\"><!-- \"1\" 이면 refresh 버튼 클릭 -->"
		page += "<input type=\"hidden\" name=\"img_seq\" value=\"" + "0" + "\">"
		page += "</form></body></html>"

		captcha := fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: idle\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: %d\r\n\r\n%s", len(page), page)

		lcon.Write([]byte(captcha))
		return
	} else if hInfo.uri == "/req_captcha/image" {

		img_bytes, digits := Make_capimg(Idle_t.Imgpath)
		lprintf(4, "[INFO] captcha make data(%s) \n", digits)

		captcha := fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: idle\r\nContent-Type: image/gif\r\nContent-Length: %d\r\n\r\n%s", len(string(img_bytes)), string(img_bytes))
		lcon.Write([]byte(captcha))
		return

	} else if hInfo.uri == "/ans_captcha" {

		var captcha string

		if strings.Contains(string(hInfo.rbuf[:]), "refresh=1") {
			captcha = fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: %s://%s:%d/req_captcha\r\n\r\n", protocol, hInfo.host, port)
		} else {

			// catpcha 검증 추가

			captcha = fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: %s://%s:%d/\r\n\r\n", protocol, hInfo.host, port)
		}

		lcon.Write([]byte(captcha))
		return

	}

	lprintf(4, "[INFO] http header protocol(%s) \n", protocol)
	// vueui.securitynetsvc.com
	lprintf(4, "[INFO] http header host(%s) \n", hInfo.host)
	// 15001
	lprintf(4, "[INFO] http header listen port(%d) \n", port)
	// /req_captcha
	lprintf(4, "[INFO] http header uri(%s) \n", hInfo.uri)

	/*
		cookie, _, _ := getHeaderValue(hInfo.rbuf, "Cookie")

		// captcha 인증 여부 확인
		if len(cookie) == 0 || !strings.Contains(cookie, "gotcha") {
			dst := strings.Split(hInfo.host, "/")
			resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: http://%s:18900/req_captcha\r\n\r\n", dst[0])
			lprintf(4, "[INFO]captcha html(%s) \n", resp)
			lcon.Write([]byte(resp))
			return
		}

		// client가 service port를 통해 해당 host로 요청을 했다.
		// 해당 데이터는 agent에서 detekt client 시 접속 port에서 ddos 공격 대상자 fqdn을 확인하기 위한 작업
		if strings.ContainsAny(lcon.RemoteAddr().String(), ":") {
			cInfos := strings.Split(lcon.RemoteAddr().String(), ":")
			ClientInfo.Lock()
			ClientInfo.m[cInfos[0]] = hInfo.host
			ClientInfo.Unlock()
		}

		lprintf(4, "[INFO] http header host(%s) \n", hInfo.host)
	*/

	pType, rst, _ := getHeaderValue(hInfo.rbuf, "PlusonType")
	var exist, statBool bool
	var ips *Ips_s
	var domain string
	ret := SUCCESS

	if rst < 0 {
		statBool = true

		// client가 service port를 통해 해당 host로 요청을 했다.
		// 해당 데이터는 agent에서 detekt client 시 접속 port에서 ddos 공격 대상자 fqdn을 확인하기 위한 작업
		ClientInfo.Lock()
		ClientInfo.m[hInfo.cIp] = hInfo.host
		ClientInfo.Unlock()

	} else {
		statBool = false
	}

	if pType == "rcs" {
		lprintf(4, "[INFO] pType rcs \n")
		goto RCS
	}

	ret, domain = app_handle(hInfo.host, hInfo.cIp, TP_HTTP)
	if ret == FAILURE {
		lprintf(1, "[FAIL] app handle fail(%s)\n", hInfo.host)
		return
	} else if ret == REPORT {
		//lprintf(1, "[FAIL] app handle report(%s)\n", hInfo.host)
		//details := "cannot serve the host(not serviced fqdn)"
		//agent_sendErr(ERR_HOST_NONE, lcon.RemoteAddr().String(), hInfo.host, strconv.Itoa(port), details)
		return
	}

	// find ips rule
	FqdnMap.RLock()
	ips, exist = FqdnMap.m[hInfo.host]
	FqdnMap.RUnlock()

	//packetSize := hInfo.hlen + hInfo.clen

	//web filter
	//if exist && webFilter(hInfo, ips, domain, lcon.RemoteAddr().String()) < 0 {
	//	return
	//}

	//go agent_stat(READ, packetSize, hInfo.host, domain, hInfo.rbuf)
RCS:
	/*
		tcon, err := net.Dial("tcp", taddr)
		if err != nil {
			lprintf(1, "[FAIL] Connecting to Nginx error (%s)", err)
			//details := "cannot connect to the NGINX - " + err.Error()
			//agent_sendErr(ERR_NGX_CONNECT, lcon.RemoteAddr().String(), hInfo.host, strconv.Itoa(port), details)
			return
		}
		defer tcon.Close()
	*/
	tcpAddr, err := net.ResolveTCPAddr("tcp", taddr)
	if err != nil {
		lprintf(1, "[ERROR] ResolveTCPAddr(%s), error(%s) \n", taddr, err.Error())
		return
	}

	tcon, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		lprintf(1, "[ERROR] DialTCP(%s), error(%s) \n", taddr, err.Error())
		return
	}
	defer tcon.Close()
	tcon.SetLinger(0)

	v := make(chan int, 1)
	go httpRoutine(lcon, tcon, v, ips, exist, port, protocol, domain, hInfo, statBool)

	// nginx -> client
	f := make(chan int, 1)
	go tpTrans(tcon, lcon, WRITE, hInfo.host, domain, port, f, statBool)

	/*
		if exist && sendBodyWithIps(hInfo, ips, lcon, tcon, true, false, domain) == CLOSE {
			f <- 1
			return
		} else if sendBody(hInfo, lcon, tcon) == CLOSE {
			lprintf(1, "[FAIL] send body fail client(%s) to (%s)\n", lcon.RemoteAddr().String(), hInfo.host)
			f <- 1
			return
		}
	*/

	for {

		select {
		case <-f:
			//lprintf(4, "[INFO] tpTrans recieve data \n")
			//v <- 1
			close(f)
			return

		case <-v:
			//lprintf(4, "[INFO] httpRoutine recieve data \n")
			//f <- 1
			close(v)
			return

		default:
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func httpRoutine(lcon, tcon net.Conn, v chan int, ips *Ips_s, exist bool, port int, protocol, domain string, hInfo HeaderInfo, statBool bool) {

	state := PASS

	for {

		//select {
		//case <-v:
		//	lprintf(1, "[INFO] httpRoutine channel close \n")
		//	close(v)
		//	return
		//default:

		// captcha 여부 체크
		// true면 req_captcha 18900 port 로 301
		//if strings.Contains(hInfo.uri, "photo_gallary") {
		// captcha 기능은 아래와 같음
		// 1. nginx captcha on 기능 -> 서비스에 접속한 모든 client 에게 captcha page 제공
		// 2. web filter, ips에 탐지된 bad client에게 captcha page 제공
		/*
			if strings.Contains(hInfo.accept, "html") && check_captcha(hInfo.cIp, port) {
				dst := strings.Split(hInfo.host, "/")
				resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: http://%s:18900/req_captcha\r\n\r\n", dst[0])
				lprintf(4, "[INFO]captcha html(%s) \n", resp)
				lcon.Write([]byte(resp))
				v <- 1
				return
			}
		*/

		// client별 caphtcha 동작
		/*
			if exist && ips.IpsInfo.captchaUse > 0 {

				// captcha 인증 여부 확인
				if strings.Contains(hInfo.accept, "html") {

					connectUrl := fmt.Sprintf("%s://%s:%d%s", protocol, hInfo.host, port, hInfo.uri)
					lprintf(4, "[INFO] client captcha use url(%s) \n", connectUrl)

					if check_captcha(hInfo.cIp, port, connectUrl) {

						cookie, _, _ := getHeaderValue(hInfo.rbuf, "Cookie")

						if len(cookie) == 0 || !strings.Contains(cookie, "gotcha") {
							dst := strings.Split(hInfo.host, "/")
							resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: http://%s:18900/req_captcha\r\n\r\n", dst[0])
							lprintf(4, "[INFO]captcha html(%s) \n", resp)
							lcon.Write([]byte(resp))
							return
						}
					}
				}
			}
		*/

		if statBool {

			var utc, kst string

			_, ret, _ := getHeaderValue(hInfo.rbuf, "StatTime")
			if ret < 0 {
				nowTime := time.Now()
				utc = nowTime.UTC().Format("2006-01-02 15:04:05")
				loc, err := time.LoadLocation("Asia/Seoul")
				if err != nil {
					lprintf(1, "[ERROR] time location err(%s) \n", err.Error())
					utc = ""
					kst = ""
				} else {
					kst = nowTime.In(loc).Format("2006-01-02 15:04:05")

					tmpBuf2, inLen2 := inHeaderValue(hInfo.rbuf, hInfo.rlen, "StatTime", utc+"^"+kst)
					hInfo.rlen += inLen2
					hInfo.hlen += inLen2

					hInfo.rbuf = make([]byte, hInfo.rlen)
					copy(hInfo.rbuf, tmpBuf2)
				}

			}

			cInfo := strings.Split(lcon.RemoteAddr().String(), ":")
			go agent_stat(READ, hInfo.hlen+hInfo.clen, hInfo.host, domain, hInfo.rbuf, cInfo[0], cInfo[1], utc, kst)
		}

		if exist {
			/*
				rst := webFilter(hInfo, ips, domain, lcon.RemoteAddr().String())
				captChaflag := false
				if rst < 0 {
					v <- 1
					return
				} else if rst == 0 {
					captChaflag = true
				}
			*/

			//if sendBodyWithIps(hInfo, ips, lcon, tcon, true, captChaflag, domain, protocol, port) == CLOSE {
			if sendBodyWithIps(hInfo, ips, lcon, tcon, true, domain, protocol, port) == CLOSE {
				v <- 1
				return
			}
		} else {
			if sendBody(hInfo, lcon, tcon) == CLOSE {
				v <- 1
				return
			}
		}

		hInfo, state = readHttpHeader(lcon, 1024, port)
		if state != PASS {
			v <- 1
			return
		}

		//}
	}

}

func webFilter(hInfo HeaderInfo, ips *Ips_s) (int, string) {

	wf := ips.IpsInfo.Wf
	//packetSize := hInfo.hlen + hInfo.clen

	// http web filter
	for idx := 0; idx < len(wf); idx++ {

		buff := wf[idx]

		value, ret, _ := getHeaderValue(hInfo.rbuf, buff.key)
		if ret == -1 {

			if buff.wCase == 1 {
				lprintf(1, "[FAIL] http header(%s) not found \n", buff.key)
				return -1, "HTTPHEADER"
			}

			lprintf(1, "[FAIL] not find http header(%s)", buff.key)
			continue
		}

		lprintf(1, "[INFO] case(%d) key(%s) value(%s) http header value(%s) \n", buff.wCase, buff.key, buff.value, value)

		switch buff.wCase {
		case 1: // 포함하지 않으면 drop, 있어야 pass
			if !strings.Contains(value, buff.value) {
				lprintf(1, "[FAIL] filter key(%s) value(%s) not like header(%s)", buff.key, buff.value, value)
				//agent_stat(WEBFILTER, packetSize, hInfo.host, domain, hInfo.rbuf)
				//go agent_noti(agent_make_wblist(BLACK, clientIp, "WEBFILTER NOT PERMITTED HTTP HEADER", hInfo.rbuf))
				/*
					if buff.defUse > 0 {
						return -1
					}
					if buff.captchaUse > 0 {
						return 0
					}
				*/
				return -1, "HTTPHEADER"
			}
		case 2: // 포함하면 drop, 없어야 pass
			if strings.Contains(value, buff.value) {
				lprintf(1, "[FAIL] filter key(%s) value(%s) like header(%s)", buff.key, buff.value, value)
				//go agent_noti(agent_make_wblist(BLACK, clientIp, "WEBFILTER PERMITTED HTTP HEADER", hInfo.rbuf))
				//agent_stat(WEBFILTER, packetSize, hInfo.host, domain, hInfo.rbuf)
				/*
					if buff.defUse > 0 {
						return -1
					}
					if buff.captchaUse > 0 {
						return 0
					}
				*/
				return -1, "HTTPHEADER"
			}
		case 3: // filter가 > 크면 drop
			num1, err := strconv.Atoi(value)
			if err != nil {
				lprintf(1, "[ERROR] header value(%s) strconv atot fail(%s)", value, err.Error())
				//go agent_noti(agent_make_wblist(BLACK, clientIp, "WEBFILTER HTTP HEADER NOT INT", hInfo.rbuf))
				//agent_stat(WEBFILTER, packetSize, hInfo.host, domain, hInfo.rbuf)
				return -1, "HTTPHEADER"
			}

			num2, err := strconv.Atoi(buff.value)
			if err != nil {
				lprintf(1, "[ERROR] header filter(%s) strconv atot fail(%s)", buff.value, err.Error())
				//agent_stat(WEBFILTER, packetSize, hInfo.host, domain, hInfo.rbuf)
				return -1, "HTTPHEADER"
			}

			if num1 <= num2 {
				lprintf(1, "[FAIL] filter key(%s) value(%d) => header(%d)", buff.key, num2, num1)
				//agent_stat(WEBFILTER, packetSize, hInfo.host, domain, hInfo.rbuf)
				//go agent_noti(agent_make_wblist(BLACK, clientIp, "WEBFILTER HTTP HEADER BETTER THAN", hInfo.rbuf))
				/*if buff.defUse > 0 {
					return -1
				}
				if buff.captchaUse > 0 {
					return 0
				}
				*/
				return -1, "HTTPHEADER"
			}

		case 4: // filter가 < 작으면 drop
			num1, err := strconv.Atoi(value)
			if err != nil {
				lprintf(1, "[ERROR] header value(%s) strconv atot fail(%s)", value, err.Error())
				//go agent_noti(agent_make_wblist(BLACK, clientIp, "WEBFILTER HTTP HEADER NOT INT", hInfo.rbuf))
				//agent_stat(WEBFILTER, packetSize, hInfo.host, domain, hInfo.rbuf)
				return -1, "HTTPHEADER"
			}

			num2, err := strconv.Atoi(buff.value)
			if err != nil {
				lprintf(1, "[ERROR] header filter(%s) strconv atot fail(%s)", buff.value, err.Error())
				//agent_stat(WEBFILTER, packetSize, hInfo.host, domain, hInfo.rbuf)
				return -1, "HTTPHEADER"
			}

			if num1 > num2 {
				lprintf(1, "[FAIL] filter key(%s) value(%d) < header(%d)", buff.key, num2, num1)
				//go agent_noti(agent_make_wblist(BLACK, clientIp, "WEBFILTER HTTP HEADER GETTER THAN", hInfo.rbuf))
				//agent_stat(WEBFILTER, packetSize, hInfo.host, domain, hInfo.rbuf)
				/*
					if buff.defUse > 0 {
						return -1
					}
					if buff.captchaUse > 0 {
						return 0
					}*/
				return -1, "HTTPHEADER"

			}

		case 5: // have
		case 6: // not have
		}
	}

	return 1, ""
}

func sendBody(hInfo HeaderInfo, lcon, tcon net.Conn) RESULT {

	// write header & body
	//lprintf(4, "[INFO] request packet client(%s) to server(%s) Wlen(%d) Content(%s)", lcon.RemoteAddr().String(), tcon.RemoteAddr().String(), len(hInfo.rbuf), string(hInfo.rbuf))

	_, err := tcon.Write(hInfo.rbuf[:])
	if err != nil {
		lprintf(1, "[FAIL] wrte error to nginx (%s)", err)
		return CLOSE
	}

	// read and write body
	blen := hInfo.clen + hInfo.hlen - hInfo.rlen

	if blen <= 0 {
		lprintf(4, "[INFO] blen(%d) PASS \n", blen)
		return PASS
	}
	//blen = 1024
	rbuf := make([]byte, blen)
	rlen := 0
	//for rlen < blen {
	for rlen < hInfo.rlen {
		Rlen, err := lcon.Read(rbuf)
		if err != nil {
			lprintf(1, "[FAIL] read error from agent (%s)", err)
			return CLOSE
		}
		rlen += Rlen

		//Wlen, err := tcon.Write(rbuf)
		_, err = tcon.Write(rbuf)
		if err != nil {
			lprintf(1, "[FAIL] write error to nginx (%s)", err)
			return CLOSE
		}

		//lprintf(4, "[INFO] sco(%s), Rlen(%d) dco(%s) Wlen(%d) write(%s) \n", lcon.RemoteAddr().String(), Rlen, tcon.RemoteAddr().String(), Wlen, string(rbuf))
		lprintf(4, "[INFO] sco(%s), Rlen(%d) dco(%s) write(%s) \n", lcon.RemoteAddr().String(), Rlen, tcon.RemoteAddr().String(), string(rbuf))
	}

	return PASS
}

func sendBodyWithIps(hInfo HeaderInfo, ips *Ips_s, lcon, tcon net.Conn, isFirst bool, domain, protocol string, port int) RESULT {

	/*
		if captChaflag {
			resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: %s://%s:%d/req_captcha\r\n\r\n", protocol, hInfo.host, port)
			lprintf(4, "[INFO]captcha html(%s) \n", resp)
			lcon.Write([]byte(resp))
			return CLOSE
		}
	*/

	if len(ips.IpsInfo.plusonType) > 0 {

		// PlusonType
		// PlusonTarget

		tmpBuf, inLen := inHeaderValue(hInfo.rbuf, hInfo.rlen, "PlusonType", ips.IpsInfo.plusonType)
		hInfo.rlen += inLen
		hInfo.hlen += inLen

		hInfo.rbuf = make([]byte, hInfo.rlen)
		copy(hInfo.rbuf, tmpBuf)

		tmpBuf2, inLen2 := inHeaderValue(hInfo.rbuf, hInfo.rlen, "PlusonTarget", ips.IpsInfo.plusonIp+","+ips.IpsInfo.plusonPort)
		hInfo.rlen += inLen2
		hInfo.hlen += inLen2

		hInfo.rbuf = make([]byte, hInfo.rlen)
		copy(hInfo.rbuf, tmpBuf2)

	}

	//packetSize := hInfo.hlen + hInfo.clen
	cntSkip := true
	ipsInfo := ips.IpsInfo

	// http header value filter
	if len(ips.IpsInfo.Wf) > 0 {
		rst, httpMsg := webFilter(hInfo, ips)
		if rst < 0 {
			lprintf(1, "[ERROR] Web Filter request url(%s) not pass(%s) \n", hInfo.uri, httpMsg)
			go agent_noti(agent_make_wblist(BLACK, lcon.RemoteAddr().String(), httpMsg, hInfo.rbuf))
			if ipsInfo.defUse > 0 {
				return CLOSE
			}
			if ipsInfo.captchaUse > 0 {
				resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: %s://%s:%d/req_captcha\r\n\r\n", protocol, hInfo.host, port)
				lprintf(4, "[INFO]captcha html(%s) \n", resp)
				lcon.Write([]byte(resp))
				return CLOSE
			}
		}

	}

	// 요청 최대 횟수, 허용 시간
	// report connect count
	if ipsInfo.cnt != 0 {
		cntSkip = false

		// url 체크 제외 문자
		for _, except := range ipsInfo.except {
			if strings.Index(hInfo.uri, except) > 0 {
				cntSkip = true
				break
			}
		}
	}

	// 요청 최대 횟수, 허용 시간
	if !cntSkip {

		if ips.IpsInfo.conCnt == nil && isFirst {
			//			ips.Lock()
			ips.Lock()
			ips.IpsInfo.conCnt = ring.New(ips.IpsInfo.period)
			for i := 0; i < ips.IpsInfo.conCnt.Len(); i++ {
				ips.IpsInfo.conCnt.Value = 0
				ips.IpsInfo.conCnt = ips.IpsInfo.conCnt.Next()
			}
			ips.Unlock()

			go createCounter(ips)

			//ips.Unlock()
		}

		if setRingcnt(ips) != PASS {
			//lprintf(4, "[IPS] request count is exceed (%d) (%s)", tcnt, ipsInfo.sname)
			lprintf(1, "[ERROR] IPS request url(%s) setRingcnt not pass \n", hInfo.uri)
			go agent_noti(agent_make_wblist(BLACK, lcon.RemoteAddr().String(), "HTTPHEADER", hInfo.rbuf))
			if ipsInfo.defUse > 0 {
				return CLOSE
			}
			if ipsInfo.captchaUse > 0 {
				resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: %s://%s:%d/req_captcha\r\n\r\n", protocol, hInfo.host, port)
				lprintf(4, "[INFO]captcha html(%s) \n", resp)
				lcon.Write([]byte(resp))
				return CLOSE
			}
		}

	}

	// 요청 길이 제한
	// max content length
	//lprintf(4, "len(%d)len(%d)", hInfo.hlen-hInfo.forwardLen+hInfo.clen, hInfo.rlen)
	if ipsInfo.maxsize != 0 && hInfo.hlen+hInfo.clen > ipsInfo.maxsize {
		lprintf(1, "[ERROR] IPS request(%s) content len is too big hlen(%d), clen(%d) maxsize(%d) \n", hInfo.uri, hInfo.hlen, hInfo.clen, ipsInfo.maxsize)
		go agent_noti(agent_make_wblist(BLACK, lcon.RemoteAddr().String(), "HTTPHEADER", hInfo.rbuf))
		if ipsInfo.defUse > 0 {
			return CLOSE
		}
		if ipsInfo.captchaUse > 0 {
			resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: %s://%s:%d/req_captcha\r\n\r\n", protocol, hInfo.host, port)
			lprintf(4, "[INFO]captcha html(%s) \n", resp)
			lcon.Write([]byte(resp))
			return CLOSE
		}
		//agent_stat(IPS, packetSize, hInfo.host, domain, hInfo.rbuf)
	}

	// HTTP 명렁어 허용
	// accept CMD
	// http header에 허용하지 않은 CMD가 들어오는지 내용 확인
	if ipsInfo.cmdList != "" && strings.Index(ipsInfo.cmdList, hInfo.cmd) < 0 {
		lprintf(1, "[ERROR] IPS request(%s) Not permitted cmd (%s)", hInfo.uri, hInfo.cmd)
		go agent_noti(agent_make_wblist(BLACK, lcon.RemoteAddr().String(), "HTTPHEADER", hInfo.rbuf))
		//agent_stat(IPS, packetSize, hInfo.host, domain, hInfo.rbuf)
		if ipsInfo.defUse > 0 {
			return CLOSE
		}
		if ipsInfo.captchaUse > 0 {
			resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: %s://%s:%d/req_captcha\r\n\r\n", protocol, hInfo.host, port)
			lprintf(4, "[INFO]captcha html(%s) \n", resp)
			lcon.Write([]byte(resp))
			return CLOSE
		}
	}

	// 요청 텍스트 필터
	// filter 전체 buff 검사 (기존)
	// filter header만 검사로 변경
	for _, filter := range ipsInfo.filter {
		//if strings.Index(string(hInfo.rbuf[:]), filter) > 0 {
		if strings.Index(string(hInfo.rbuf[:hInfo.hlen]), filter) > 0 {
			lprintf(1, "[ERROR] IPS request(%s) Not permitted text (%s)", hInfo.uri, filter)
			go agent_noti(agent_make_wblist(BLACK, lcon.RemoteAddr().String(), "HTTPHEADER", hInfo.rbuf))
			//agent_stat(IPS, packetSize, hInfo.host, domain, hInfo.rbuf)
			if ipsInfo.defUse > 0 {
				return CLOSE
			}
			if ipsInfo.captchaUse > 0 {
				resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: %s://%s:%d/req_captcha\r\n\r\n", protocol, hInfo.host, port)
				lprintf(4, "[INFO]captcha html(%s) \n", resp)
				lcon.Write([]byte(resp))
				return CLOSE
			}
		}
	}

	// write header
	if _, err := tcon.Write(hInfo.rbuf[:hInfo.hlen]); err != nil {
		return CLOSE
	} else if hInfo.clen == 0 {
		return PASS
	}

	// write body
	// body 검사는 별도로 개발 예정
	/*
		for _, filter := range ipsInfo.filter {
			if strings.Index(string(hInfo.rbuf[hInfo.hlen:]), filter) > 0 {
				lprintf(1, "[IPS] Not permitted text (%s)", filter)
				agent_stat(IPS, packetSize, hInfo.host, domain, hInfo.rbuf)
				return CLOSE
			}
		}
	*/
	if _, err := tcon.Write(hInfo.rbuf[hInfo.hlen:]); err != nil {
		return CLOSE
	}

	// read and write body
	blen := hInfo.clen - (hInfo.rlen - hInfo.hlen)
	rbuf := make([]byte, 1024)
	rlen := 0
	for rlen < blen {
		llen, err := lcon.Read(rbuf)
		if err != nil {
			return CLOSE
		}

		rlen += llen
		/*
			// body 검사는 별도로 개발 예정
			for _, filter := range ipsInfo.filter {
				if strings.Index(string(rbuf), filter) > 0 {
					lprintf(1, "[IPS] Not permitted text (%s)", filter)
					agent_stat(IPS, packetSize, hInfo.host, domain, hInfo.rbuf)
					return CLOSE
				}
			}
		*/
		if _, err := tcon.Write(rbuf); err != nil {
			return CLOSE
		}
	}

	return PASS
}

////////////////////////////////////////////////////////////////////////////////////////////
func tpTcpTarget(lcon net.Conn, taddr string, dom, fqdn string, port int) {

	lprintf(4, "[INFO] tpTcpTarget call \n")

	defer lcon.Close()
	//var host string
	var ret RESULT

	BufSize := 1024
	Rbuf := make([]byte, BufSize)
	var readLen int = 0

	var slowread bool
	cInfo := strings.Split(lcon.RemoteAddr().String(), ":")
	clientIp := cInfo[0]

	for {
		var rlen int
		var err error
		rlen, err = lcon.Read(Rbuf[readLen:])
		//lprintf(4, "rbuf(%s)", string(rbuf))
		if err != nil {
			lprintf(1, "[WARN] Http read failure or time out (%s)", err)
			if slowread {
				// block client
				lprintf(4, "[AGENT] Notify BlackList Client (%s)", lcon.RemoteAddr().String())
				go agent_noti(agent_make_wblist(BLACK, lcon.RemoteAddr().String(), "SLOW READ", nil))
			}
			return
		}

		readLen = readLen + rlen

		if Slowread.ttl != 0 {
			if !slowread && readLen < Slowread.size {
				lcon.SetReadDeadline(time.Now().Add(time.Second * time.Duration(Slowread.ttl)))
				slowread = true
				continue
			}

			if slowread || readLen < Slowread.size {
				continue
			}

			if slowread && readLen > Slowread.size {
				slowread = false
			}

			//pass only
			if !slowread && readLen > Slowread.size {
				//pass
			}
		}
		break

	}

	lprintf(4, "[INFO] read client first (%d)", readLen)

	readd := string(Rbuf[:readLen])
	lprintf(4, "[INFO] TCP CONNECT len (%d), data (%s)", readLen, readd)
	lprintf(4, "[INFO] tcp packet from (%s)\n", lcon.RemoteAddr().String())

	//call application
	ret, _ = app_handle(dom, clientIp, TP_TCP)
	if ret == FAILURE {
		return
	}

	// do proxy
	tcon, err := net.Dial("tcp", taddr)
	if err != nil {
		lprintf(1, "[FAIL] TCP CONNECT error (%s)(%s)", taddr, err)
		return
	}
	defer tcon.Close()

	tcon.Write(Rbuf[:readLen])
	go tpTrans(tcon, lcon, WRITE, fqdn, "NULL", port, nil, false)
	tpTrans(lcon, tcon, READ, fqdn, "NULL", port, nil, false)
}

// parking http
func tpHttpTarget3(lcon net.Conn, ip string, port int) {

	lprintf(4, "[INFO] start http proxy read -target ip (%s) port(%d) ", ip, port)

	//var flag bool // client http packet 서비스 여부

	// connect nginx ONCE at first
	hInfo, state := readHttpHeader(lcon, 1024, port)
	defer lcon.Close()
	if state != PASS {
		return
	}

	/*
		myips := "*.ipip.kr what-is-myip.net what-is-myip.org ip-servers.net ip-servers.org edge-ipconfig.com edge-ipconfig.net edge-findip.com edge-findip.net"
		if strings.Contains(myips, hInfo.host) {

			lprintf(4, "[INFO] request host(%s) \n", hInfo.host)

			resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: idle\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s", len(lcon.RemoteAddr().String()), lcon.RemoteAddr().String())
			lcon.Write([]byte(resp))
			return
		}
	*/

	/*
		pm := ProxyMap.m

		pInfo, exists := pm[hInfo.host]
		if exists {
			flag = true
		} else {
			for key, value := range pm {
				if value.protocol == HTTP_BLOCK && strings.Contains(hInfo.host, key) && compare_domain(hInfo.host, key) {
					flag = true
					break
				}
			}
		}

		if !flag {
			lprintf(1, "[FAIL] requset host(%s) not service \n", hInfo.host)
			return
		}
	*/

	targetIp := strings.Split(ip, "&")
	for i := 0; i < len(targetIp); i++ {

		ip := targetIp[(cls.SvrIdx+i)%len(targetIp)]
		taddr := fmt.Sprintf("%s:%d", ip, port)

		tcon, err := net.Dial("tcp", taddr)
		if err != nil {
			lprintf(1, "[FAIL] HTTP Connecting to target(%s) error (%s)", taddr, err)
			continue
		}
		defer tcon.Close()

		// nginx -> client
		go tpTrans(tcon, lcon, WRITE, hInfo.host, "", port, nil, false)

		if sendBody(hInfo, lcon, tcon) == CLOSE {
			lprintf(1, "[FAIL] send body fail client(%s) to (%s)\n", lcon.RemoteAddr().String(), hInfo.host)
			return
		}

		// read next header and body
		for {
			hInfo, state = readHttpHeader(lcon, 1024, port)
			if state != PASS {
				return
			}

			if sendBody(hInfo, lcon, tcon) == CLOSE {
				return
			}
		}

	}
}

// basic proxy tcp
func tpTcpTarget2(lcon *net.TCPConn, ip string, port int) {

	defer lcon.Close()

	BufSize := 1024
	Rbuf := make([]byte, BufSize)

	var readLen int = 0
	var slowread bool

	for {
		var rlen int
		var err error
		rlen, err = lcon.Read(Rbuf[readLen:])
		//lprintf(4, "rbuf(%s)", string(rbuf))
		if err != nil {
			lprintf(1, "[WARN] tcp read failure or time out (%s)", err)

			/*

				if slowread {
					// block client
					lprintf(4, "[AGENT] Notify BlackList Client (%s)", lcon.RemoteAddr().String())
					agent_noti(agent_make_wblist(BLACK, lcon.RemoteAddr().String()))
				}

			*/

			return
		}

		readLen = readLen + rlen

		//lprintf(4, "header get11111111(%s)readlen(%d),rlen(%d)", string(rbuf), readLen, rlen)
		// check slowread at first
		if Slowread.ttl != 0 {
			if !slowread && readLen < Slowread.size {
				lcon.SetReadDeadline(time.Now().Add(time.Second * time.Duration(Slowread.ttl)))
				slowread = true
				continue
			}

			if slowread || readLen < Slowread.size {
				continue
			}

			if slowread && readLen > Slowread.size {
				slowread = false
			}

			//pass only
			if !slowread && readLen > Slowread.size {
				//pass
			}
		}
		break
	}

	lprintf(4, "[INFO] TCP CONNECT len (%d), data (%s)", readLen, string(Rbuf[:readLen]))
	lprintf(4, "[INFO] tcp packet from (%s)\n", lcon.RemoteAddr().String())

	targetIp := strings.Split(ip, "&")
	for i := 0; i < len(targetIp); i++ {

		ip := targetIp[(cls.SvrIdx+i)%len(targetIp)]
		taddr := fmt.Sprintf("%s:%d", ip, port)

		tcon, err := net.Dial("tcp", taddr)
		if err != nil {
			lprintf(1, "[FAIL] TCP Connecting to target(%s) error (%s)", taddr, err)
			continue
		}
		defer tcon.Close()

		tcon.Write(Rbuf[:readLen])
		go tpTrans(tcon, lcon, WRITE, "NULL", "NULL", port, nil, false)
		tpTrans(lcon, tcon, READ, "NULL", "NULL", port, nil, false)

		break
	}
}

func tpTrans(sco, dco net.Conn, wr int, host, domain string, port int, f chan int, statBool bool) {

	lprintf(4, "[INFO] tpTrans packet read(%s) to write(%s)", sco.RemoteAddr().String(), dco.RemoteAddr().String())

	BufSize := 1024
	Rbuf := make([]byte, BufSize)

	for {

		//select {
		//case <-f:
		//	lprintf(1, "[INFO] tpTrans channel close \n")
		//	close(f)
		//	return
		//default:

		Rlen, err := sco.Read(Rbuf)
		if err != nil {

			if f != nil {
				//lprintf(1, "[ERROR] TCP(%s) read Close(%s) channel close  \n", sco.RemoteAddr().String(), err.Error())
				f <- 1
				return
			}

			if err == io.EOF {
				lprintf(4, "[INFO] TCP(%s) read Close(EOF) \n", sco.RemoteAddr().String())
				return
			}

			lprintf(1, "[ERROR] TCP(%s) read Close(%s) \n", sco.RemoteAddr().String(), err.Error())
			return
		}

		lprintf(4, "[INFO] sco(%s) Rlen(%d) dco(%s) write(%s) \n", sco.RemoteAddr().String(), Rlen, dco.RemoteAddr().String(), string(Rbuf[:Rlen]))
		if statBool {
			cInfo := strings.Split(dco.RemoteAddr().String(), ":")
			go agent_stat(wr, Rlen, host, domain, Rbuf[:Rlen], cInfo[0], cInfo[1], "", "")
		}

		_, err = dco.Write(Rbuf[:Rlen])
		//Wlen, err := dco.Write(Rbuf[:Rlen])
		if err != nil {
			lprintf(1, "[ERROR] TCP write error(%s), Rlen(%d)", err, Rlen)
			return
		}
		//}
		//lprintf(4, "[INFO] Wlen(%d)\n", Wlen)
	}

	return
}
