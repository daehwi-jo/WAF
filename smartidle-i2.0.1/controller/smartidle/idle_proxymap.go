package smartidle

import (
	"io/ioutil"
	"strconv"

	//"strconv"
	"net"
	"strings"
	"sync"
	"time"

	"charlie/i0.0.2/cls"
)

var Agent int = -1

type NGX_BLOCK uint

const (
	COMMON_BLOCK NGX_BLOCK = iota
	HTTP_BLOCK
	STREAM_BLOCK
)

type BlockInfo struct {
	ssl bool
	crt string
	key string

	block NGX_BLOCK

	port   int
	fqdn   string
	domain string

	//close chan bool
	ln     net.Listener
	ln_flg bool
}

// http, tcp basic proxy
type ProxyInfo struct {
	protocol NGX_BLOCK

	domain  string
	lPort   int    //listen port
	tServer string // target server
	tPort   int    // target port
}

var ClientInfo = struct {
	sync.RWMutex
	m map[string]string // key - clientIp:service(dst) port
}{m: make(map[string]string)} // value - service fqdn

var ProxyMap = struct {
	mCnt int                  // http map + tcp map
	m    map[string]ProxyInfo // http domain key, tcp listen port key
}{m: make(map[string]ProxyInfo)}

var PortMap = struct {
	sync.RWMutex
	m map[int]BlockInfo
}{m: make(map[int]BlockInfo)}

var Clientconf = struct {
	sync.RWMutex
	Client_m map[string]time.Time
}{Client_m: make(map[string]time.Time)}

func gset_sphere_data(domain, domver, ipsver, wfver string, reload_flg bool, agentType, clientIp string) RESULT {
	//http: //192.168.18.47:8080/smartnginx/2
	/*req, err := http.NewRequest("GET", "http://"+addr+"/smartnginx/reqconf", strings.NewReader(domain))
	if err != nil {
		lprintf(4, "[FAIL] Request URL(%s) http.Get fail", err.Error())
		return types.FAILURE
	}
	client := &http.Client{}
	resp, err := client.Do(req)*/

	//lprintf(4, "[INFO] domver(%s), ipsver(%s), wfver(%s) \n", domver, ipsver, wfver)
	lprintf(4, "[INFO] domver(%s), ipsver(%s) \n", domver, ipsver)

	if domver == "" {
		domver = "0"
	}
	if ipsver == "" {
		ipsver = "0"
	}
	/*
		if wfver == "" {
			wfver = "0"
		}
	*/

	//domain -> innogs.com
	//bodyData := domain + "/" + domver + "/" + ipsver + "/" + wfver + "/" + agentType
	bodyData := domain + "/" + domver + "/" + ipsver + "/" + agentType

	if agentType == "nonagent" {
		bodyData += "/" + clientIp + "/" + cls.ListenIP
	}

	lprintf(4, "[INFO] Request body data(%s) \n", bodyData)

	resp, err := cls.HttpSendBody(cls.TCP_SPHERE, "GET", "smartnginx/reqConf", []byte(bodyData), true)
	if err != nil {
		lprintf(1, "[FAIL] http response(maybe sphere off) fail (%s)", err.Error())
		return FAILURE
	}
	//defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		lprintf(1, "[FAIL] Read resp body fail (%s)", err.Error())
		resp.Body.Close()
		return FAILURE
	}
	resp.Body.Close()

	str_data := string(data)
	if strings.Contains(str_data, "Not Found") {
		lprintf(1, "[INFO] sphere message 'Not Found'")
		return IGNORE
	}
	//lprintf(4, "sphere(%s)", string(data))

	// 기동 시
	if strings.HasPrefix(str_data, "domainlist") {
		lprintf(4, "[SPHERE] DomainList Parse")

		domlist := strings.Split(str_data, ",")

		for i := 1; i < len(domlist); i++ {
			lprintf(4, "[SPHERE] Parsed Domain is (%s)", domlist[i])

			if i == len(domlist)-1 {
				reload_flg = true
			}

			ret := gset_sphere_data(domlist[i], "", "", "", reload_flg, agentType, clientIp)
			if ret != SUCCESS {
				if ret == FAILURE {
					lprintf(1, "[ERROR] Not connected with Sphere now.")
					return ret
				}
			}
		}
		return SUCCESS
	}

	//ret := types.SUCCESS
	ret := ngx_conf_sync(str_data, domain, domver, ipsver, wfver, reload_flg)

	return ret

}

func do_map(host, clientIp string, typ int) (RESULT, string) {

	lprintf(4, "[INFO] do map host(%s), type(%d) \n", host, typ)

	if len(host) == 0 {
		lprintf(1, "[FAIL] No hostname. ")
		return FAILURE, ""
	}

	var domain string
	var ret RESULT
	var agentType string

	// domain, host check
	//host = "innogs.com"
	if typ == TP_HTTP || typ == Agent {

		// get domain
		resp, err := cls.HttpSendBody(cls.TCP_SPHERE, "GET", "smartnginx/getDomain", []byte(host), true)
		if err != nil {
			lprintf(1, "[FAIL] http response fail(%s)", err.Error())
			return FAILURE, ""
		}

		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			lprintf(1, "[FAIL] Read resp body read fail(%s)", err.Error())
			resp.Body.Close()
			return FAILURE, ""
		}
		resp.Body.Close()

		respData := string(data)
		lprintf(4, "[INFO] sphere get domain(%s) \n", respData)

		if strings.Contains(respData, "NOT Service") {
			//lprintf(1, "[FAIL] host(%s) not service \n", host)
			return REPORT, ""
		}

		respDatas := strings.Split(respData, "/")
		if len(respDatas) > 2 {
			domain = respDatas[1]
			agentType = respDatas[2]
		}

		//domain = "securitynet-test.com"

	} else {
		domain = host
	}

	Ngxconf.RLock()
	dominfo, exist := Ngxconf.Domain_m[domain]
	Ngxconf.RUnlock()

	if typ != Agent && exist {

		//check ttl
		lprintf(4, "domain(%s) search map exist", domain)
		now := time.Now()

		// check non agent client ip
		if agentType == "nonagent" {
			Clientconf.RLock()
			inTime, exist := Clientconf.Client_m[clientIp]
			Clientconf.RUnlock()

			//now := time.Now()

			// map에 client 정보가 있는경우 ttl 비교
			if exist {
				lprintf(4, "clientIp(%s) search map exist", clientIp)
				diff := int(now.Sub(inTime).Seconds())
				lprintf(4, "[INFO] diff(%d), Intime(%d) \n", diff, inTime)
				if diff < Idle_t.MAP_TTL {
					lprintf(4, "[INFO] client ttl not yet \n")
					return SUCCESS, domain
				}

				now = inTime.Add(2 * time.Second)
			}

			Clientconf.Lock()
			Clientconf.Client_m[clientIp] = now
			Clientconf.Unlock()

			lprintf(4, "clientIp(%s) ttl finish", clientIp)
		} else {
			//now := time.Now()
			diff := int(now.Sub(dominfo.Intime).Seconds())

			lprintf(4, "[INFO] diff(%d), Intime(%d) \n", diff, dominfo.Intime)
			if diff < Idle_t.MAP_TTL {
				lprintf(4, "[INFO] domain ttl not yet \n")
				return SUCCESS, domain
			}

			//go sphere again
			dominfo.Intime = dominfo.Intime.Add(2 * time.Second)
			dominfo.AgentType = agentType

			Ngxconf.Lock()
			Ngxconf.Domain_m[domain] = dominfo
			Ngxconf.Unlock()

			lprintf(4, "[INFO] domain ttl finish \n")

			/*
				if diff > Idle_t.MAP_TTL {
					lprintf(4, "[INFO] domain ttl finish \n")

					//go sphere again
					dominfo.Intime = dominfo.Intime.Add(2 * time.Second)
					dominfo.AgentType = agentType

					Ngxconf.Lock()
					Ngxconf.Domain_m[domain] = dominfo
					Ngxconf.Unlock()

					ret = gset_sphere_data(domain, dominfo.Dom_ver, dominfo.Ips_ver, dominfo.Wf_ver, true, agentType, clientIp)
					if ret != SUCCESS {
						return ret, ""
					}
				}

				lprintf(4, "[INFO] domain ttl not yet \n")
				return SUCCESS, domain
			*/

		}
	}

	//map 존재하지 않고, agent type 이면
	ret = gset_sphere_data(domain, dominfo.Dom_ver, dominfo.Ips_ver, dominfo.Wf_ver, true, agentType, clientIp)
	if ret != SUCCESS {
		return ret, domain
	}

	return SUCCESS, domain
}

func setInitPortMap(portinfo BlockInfo) bool {

	//var noti bool = true

	port := portinfo.port
	lprintf(4, "[LOCK] start port map key(%d) ", port)

	PortMap.RLock()
	oriinfo, exist := PortMap.m[port]
	PortMap.RUnlock()

	if exist {
		if (port == 80 || port == 443 || port == 1080) || oriinfo.ssl == false { //|| (portinfo.crt == oriinfo.crt && portinfo.key == oriinfo.key) {
			lprintf(4, "[INFO] PORT already OPEN (%d) ", port)
			return false
		}

		//if oriinfo.ssl == true && oriinfo.ln_flg == true {
		if oriinfo.ssl && oriinfo.ln_flg {
			return false

			/*
				noti = false

					err := oriinfo.ln.Close()
					if err != nil {
						lprintf(1, "[ERROR] socket close error(%s) \n", err.Error())
						return true
					}


				lprintf(4, "[INFO] PORT REOPEN (%d) ,CERT (%s)", port, portinfo.crt)
			*/
		}
	}

	//inform port to agent
	//if noti == true {
	lprintf(4, "[AGENT] Notify WhiteList Port (%d)", port)
	agent_noti(agent_make_wblist(WHITE, strconv.Itoa(port), "PORT OPEN", nil))
	//}

	//portinfo.close = make(chan bool)
	//lprintf(4, "port (%d) close chan make", port)

	//	PortMap.Lock()
	//PortMap.m[port] = portinfo
	//	PortMap.Unlock()

	go tpTcpProxy(portinfo)

	//if portinfo.ssl == true && (port != 80 && port != 443 && port != 1080) {
	//	time.Sleep(1 * time.Millisecond)
	//}

	lprintf(4, "[LOCK] finish get host port map (%d) ", port)

	return true
}

func portChan(close chan bool, port int, ln net.Listener) {

	for {
		select {
		case <-close:
			lprintf(4, "TLS PORT LISTEN CHANGE (%d)", port)
			ln.Close()
			//	close(portinfo.close)
			return

		default:
		}
	}
}

/*func setInitFqdnMap(fqdn string, domain string, exist bool, block NGX_BLOCK) bool {
	var fInfo FqdnInfo

	lprintf(5, "[LOCK] start fqdn map key(%s) ", fqdn)
	FqdnMap.RLock()
	fInfo, find := FqdnMap.m[fqdn]
	FqdnMap.RUnlock()

	if find {
		lprintf(4, "[INFO] the fqdn is exist in the fqdnmap (%s) ", fqdn)
		return false
	}

	fInfo.domain = domain
	fInfo.exist = exist
	fInfo.block = block
	fInfo.inTime = time.Now()

	FqdnMap.Lock()
	FqdnMap.m[fqdn] = fInfo
	FqdnMap.Unlock()

	lprintf(5, "[LOCK] finish get host fqdn map ")
	return true
}*/
