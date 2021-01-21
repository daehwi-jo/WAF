package smartidle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"charlie/i0.0.2/cls"
)

var lprints func(int, string, ...interface{}) = cls.Lprints

type StatInfo struct {
	domain string
	ip     string
	port   string

	contents string
	wlen     int
	rlen     int
	//total_len int
}

type JsonInfo struct {
	Juuid     string    `json:"uuid"`
	Jdevid    int       `json:"devid"`
	Jsource   string    `json:"source"`  // idle
	Jcommand  int       `json:"command"` // 0:insert, 1:delete
	Jlist     int       `json:"list"`    // 0:white 1:black
	Reason    string    `json:"reason"`  // 사유
	Buff      string    `json:"buff"`
	Jkeylists []Keylist `json:"keyList"`
}
type Keylist struct {
	Jip     string `json:"ip"`
	Jport   int    `json:"port"`
	Jperiod int    `json:"period"`
}

type Slowread_s struct {
	ttl       int
	size      int
	blocktime string
}

type WITHAGENT uint

const (
	/*	SLOWREAD WITHAGENT = iota
		SPHEREIP
		BOTH
		DOMAIN
		NONE*/
	BLACK WITHAGENT = iota
	WHITE

	STAT
	ERR
)

type ERRCODE uint

const (
	ERR_IDLE_LSN ERRCODE = iota + 100
	ERR_IDLE_ACCT

	ERR_PORT_NONE ERRCODE = 110
	ERR_HOST_NONE         = 111
	ERR_HOST_PKT          = 112

	ERR_FILE_CERT   ERRCODE = 120
	ERR_FILE_CAPIMG         = 121

	ERR_FILTER_BLOCK ERRCODE = 150
	ERR_IPS_BLOCK            = 151

	ERR_NGX_CONNECT ERRCODE = 200
	ERR_NGX_WR              = 201
	ERR_NGX_RELOAD          = 202
	ERR_NGX_ROLLB           = 203
	ERR_NGX_CONF            = 204

	ERR_SPH_CONNECT ERRCODE = 300

	ERR_AGT_CONNECT ERRCODE = 400

	ERR_WHICH ERRCODE = 500
)

/*
func agent_sendErr(errcode ERRCODE, client_ip, host, port, details string) {

	/*
		msg := "name:idle, errcode:" + strconv.Itoa(int(errcode))
		msg += ", client_ip:" + client_ip
		msg += ", host:" + host
		msg += ", port:" + port
		msg += ", details:" + details

		ret := agent_http(STAT, []byte(msg), 1)
		if ret == 200 {
			lprintf(4, "[AGENT] Send ERRCODE - ERRCODE(%d) clientIP(%s) host(%s) port(%s) details(%s)", int(errcode), client_ip, host, port, details)
		}
*/

//	agent_stat(client_ip, host, port, details, -1, 0, nil, errcode)

//}

//go agent_sendStat(READ, packetSize, hInfo.host, doamin, hInfo.rbuf)

/*
func agent_sendStat(pTtpe, pSize int, fqdn, domain string, p []byte) {

	agent_stat(pTtpe, pSize, fdqn, domain, p)
}
*/

/*
func agent_sendHeader(client_ip, host string, wr, leng int, header []byte) {

	agent_stat(client_ip, host, "", "", wr, leng, header, 1)
}
*/

func mornitor_agent_file(time_intv int, fexist, fread string) {

	lprintf(4, "[INFO] Mornitoring agent file each (%d)sec, files(%s,%s)\n", time_intv, fexist, fread)

	d := time.Duration(time_intv)

	for {
		time.Sleep(d * time.Second)
		if _, err := os.Stat(fexist); os.IsNotExist(err) {
			continue
		}

		/*
			사용안함 2020-11-25
			v, r := cls.GetTokenValue("nodeID", fread)
			if r != cls.CONF_ERR {
				Idle_t.NodeID, _ = strconv.Atoi(v)
				lprintf(4, "[AGENT] NodeID is (%d)", Idle_t.NodeID)

				//os.Remove(fexist)
				//os.Remove(fread)

				//lprintf(4, "[AGENT] Deleted NodeID files.")

				gset_sphere_data("all", v, "0", "0", false, "agent", "")
				//gset_sphere_data("all", v, "0", "0", true) sphere test data 이용 시

				//continue
			}
		*/

		v, r := cls.GetTokenValue("DOMAIN", fread)
		if r != cls.CONF_ERR {
			//lprintf(4, "v(%s)", v)
			domain := strings.Split(v, "^")
			for i := 0; i < len(domain); i++ {

				lprintf(4, "[INFO] agent notify domain(%s)", domain[i])

				ret, _ := do_map(domain[i], cls.ListenIP, Agent)
				if ret == IGNORE {
					lprintf(4, "[XML] DOMAIN Status : no data, not changed, or same version")
				}
			}

			//os.Remove(fexist)
			//os.Remove(fread)
			//lprintf(4, "[AGENT] Deleted DOMAIN files.")
			//continue
		}

		v, r = cls.GetTokenValue("SLOWREAD", fread)
		if r != cls.CONF_ERR {
			sr := strings.Split(v, "^")
			if len(sr) != 3 {
				lprintf(1, "[WARN] Slowread data get wrong, set 0")
				Slowread.ttl = 0
				Slowread.size = 0
				Slowread.blocktime = ""
			} else {
				Slowread.ttl, _ = strconv.Atoi(strings.TrimSpace(sr[0]))
				Slowread.size, _ = strconv.Atoi(strings.TrimSpace(sr[1]))
				Slowread.blocktime = strings.TrimSpace(sr[2])
			}
			lprintf(4, "[AGENT] SlowRead set - ttl(%d) size(%d) blocktime(%s)", Slowread.ttl, Slowread.size, Slowread.blocktime)
		}

		v, r = cls.GetTokenValue("SPHERE", fread)
		if r != cls.CONF_ERR {
			cls.SetServerIp(cls.TCP_SPHERE, v)
			lprintf(4, "[AGENT] Sphere IP has changed (%s)", v)
		}

		v, r = cls.GetTokenValue("DELCACHE", fread)
		if r != cls.CONF_ERR {

			var fp string
			fps := strings.Split(v, "^")
			for i := 0; i < len(fps); i++ {
				fp = Idle_t.CACHE_DIR + fps[i]

				files, err := ioutil.ReadDir(fp)
				if err != nil {
					lprintf(1, "[ERROR] read dir(%s), err(%s) \n", fp, err.Error())
					continue
				}

				var rpath string
				for _, k := range files {

					if fp[len(fp)-1] == '/' {
						rpath = fmt.Sprintf("%s%s", fp, k.Name())
					} else {
						rpath = fmt.Sprintf("%s/%s", fp, k.Name())
					}

					lprintf(4, "[INFO] cache dir(%s) remove\n", rpath)
					os.RemoveAll(rpath)
				}
			}
		}

		os.Remove(fexist)
		os.Remove(fread)
		lprintf(4, "[AGENT] Deleted files.")
	}
}
func agent_make_wblist(typ WITHAGENT, data, reason string, buff []byte) []byte {
	var jsoninfo JsonInfo

	jsoninfo.Jsource = "idle"
	jsoninfo.Jcommand = 0
	jsoninfo.Jkeylists = make([]Keylist, 1)
	jsoninfo.Reason = reason

	if buff != nil {
		jsoninfo.Buff = string(buff)
	}

	if typ == WHITE { //data is port
		jsoninfo.Jlist = 0
		jsoninfo.Jkeylists[0].Jip = "0"
		jsoninfo.Jkeylists[0].Jport, _ = strconv.Atoi(data)

	} else if typ == BLACK { //data is client ip:port
		tmp := strings.Split(data, ":")

		jsoninfo.Jlist = 1
		jsoninfo.Jkeylists[0].Jip = tmp[0]
		jsoninfo.Jkeylists[0].Jport, _ = strconv.Atoi(tmp[1])
		jsoninfo.Jkeylists[0].Jperiod, _ = strconv.Atoi(Slowread.blocktime)
	}

	out, _ := json.Marshal(jsoninfo)
	//lprintf(4, "json(%s)", string(out))
	return out

}

func agent_noti(out []byte) RESULT { //for black ,white list

	// smartagent/notifire

	req, err := http.NewRequest("GET", "http://"+cls.ListenIP+":"+Idle_t.AGENT_PORT+"/smartagent/notifire", bytes.NewReader(out))
	if err != nil {
		lprintf(1, "[FAIL] Agent GET URL fail(%s)", err.Error())
		return FAILURE
	}

	req.Header.Set("Connection", "close")
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)

	if err != nil {
		lprintf(1, "[FAIL] http json response(maybe Agent off) fail (%s)", err.Error())
		return FAILURE
	}
	defer resp.Body.Close()

	return SUCCESS
}

func agent_stat(pt, ps int, fqdn, domain string, p []byte, srcIp, srcPort, utc, kst string) {

	if Idle_t.MODE == 1 { // basic proxy
		return
	}

	/*
		packet type(read, write)
		packet size
		fqdn
		domain
		packet
	*/

	var pType string
	if pt == READ {
		pType = "READ"
	} else if pt == WRITE {
		pType = "WRITE"
	} else if pt == IPS {
		pType = "IPS"
	} else if pt == WEBFILTER {
		pType = "WEBFILTER"
	}

	// http header write
	//data := fmt.Sprintf("smartidle,%s,%d,%s,%s,%s,%s", pType, ps, fqdn, domain, string(p), srcIp)
	var data string
	if len(utc) > 0 {
		data = fmt.Sprintf("smartidle,%s,%s,%d,%s,%s,%s,%s,%s", pType, fqdn, ps, domain, srcIp, srcPort, utc, kst)
	} else {
		data = fmt.Sprintf("smartidle,%s,%s,%d,%s,%s,%s", pType, fqdn, ps, domain, srcIp, srcPort)
	}

	lprintf(4, "[INFO] stat data(%s) \n", data)

	agentStat([]byte(data))

}

func agentStat(body []byte) int {

	addrs := fmt.Sprintf("http://%s:%s/smartagent/stat", cls.ListenIP, Idle_t.AGENT_PORT)
	//addrs := fmt.Sprintf("http://%s:%s/smartagent/stat", cls.ListenIP, Idle_t.STAT_PORT)
	req, err := http.NewRequest("GET", addrs, bytes.NewBuffer(body))
	if err != nil {
		lprintf(1, "[ERROR] http new request err(%s) \n", err.Error())
		return -1
	}

	//req.Header.Add("User-Agent", "Crawler")
	req.Header.Set("Connection", "close")
	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return -1
	}
	resp.Body.Close()

	return 1
}
