package smartidle

import (
	"bytes"
	"fmt"
	"os"

	//"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"

	"sync"

	types "smartidle/smartidle-i2.0.1/model/smartidle" //data structure

	"charlie/i0.0.2/cls"
)

type RESULT uint

const (
	FAILURE RESULT = iota
	SUCCESS
	IGNORE
	REPORT

	PASS
	CLOSE
)

//#pragma warning disable warning-list

var FunConHandler func(net.Conn, http.ConnState)

var lprintf func(int, string, ...interface{}) = cls.Lprintf

var Idle_t types.Idle_s

var captcha_m map[int]types.ClientInfo
var timer_off_seq chan int //captcha timer

var Ngxconf types.NgxconfInfo

//var Clientconf types.Clientconf
var Slowread Slowread_s

func App_conf(fname string) int {
	//	CONF_FILE = fname

	lprintf(4, "[INFO] *** IDLE CONF PATH (%s)\n", fname)

	if init_basic_proxy(fname) == 0 {
		init_basic_data(fname)
	}

	var portinfo BlockInfo

	portinfo.port = 80
	portinfo.block = HTTP_BLOCK
	portinfo.ssl = false
	portinfo.fqdn = "80port"

	if Idle_t.MODE == 1 { //basic proxy (http, tcp proxy)

		proxyMap := ProxyMap
		var wait sync.WaitGroup
		wait.Add(proxyMap.mCnt)

		for _, val := range proxyMap.m {
			go tpBasicProxy(val)
		}

		wait.Wait()

	} else {
		go tpTcpProxy(portinfo)

		load_conf(Idle_t.NGX_PATH + "/conf/httpblk.conf")
		load_conf(Idle_t.NGX_PATH + "/conf/streamblk.conf")
	}

	return 0
}

func init_basic_proxy(fname string) int {

	// smartidle mode check(parking - 1, nginx - 0)

	v, r := cls.GetTokenValue("PROXY_INFO", fname)
	if r == cls.CONF_ERR {
		lprintf(1, "[INFO] idle-nginx mode \n")
		return Idle_t.MODE
	}

	cnt, err := strconv.Atoi(v)
	if err != nil {
		lprintf(1, "[ERROR] PROXY_INFO value type not integer \n")
		os.Exit(1)
	}

	Idle_t.MODE = 1
	ProxyMap.mCnt = cnt
	lprintf(1, "[INFO] idle proxy mode, proxy info cnt(%d)\n", cnt)

	// proxy info set
	for i := 0; i < cnt; i++ {
		var pm ProxyInfo
		var s, key string

		if i < 10 {
			s = fmt.Sprintf("PROXY_INF0%d", i)
		} else {
			s = fmt.Sprintf("PROXY_INF%d", i)
		}

		vs, r := cls.GetTokenValue(s, fname)
		if r == cls.CONF_ERR {
			lprintf(1, "[FAIL] %s value read fail, PROXY_INFO(%d) \n", s, cnt)
			os.Exit(1)
		}

		idx := strings.Split(vs, ",")
		if len(idx) < 5 {
			lprintf(1, "[FAIL] %s value(%s) read fail, protocol,http(domain) or tcp(NULL),listen port,target(service) ip,target(service) port\n", s, vs)
			os.Exit(1)
		}

		if idx[0] == "HTTP" {
			pm.protocol = HTTP_BLOCK
			key = idx[1]
		} else if idx[0] == "TCP" {
			pm.protocol = STREAM_BLOCK
			key = idx[2]
		} else {
			lprintf(1, "[ERROR] check protocol type(%s) \n", idx[0])
			os.Exit(1)
		}

		pm.domain = idx[1]
		pm.lPort, err = strconv.Atoi(idx[2])
		if err != nil {
			lprintf(1, "[FAIL] port(%s) not integer \n", idx[2])
			os.Exit(1)
		}
		pm.tServer = idx[3]
		pm.tPort, err = strconv.Atoi(idx[4])
		if err != nil {
			lprintf(1, "[FAIL] port(%s) not integer \n", idx[4])
			os.Exit(1)
		}

		for _, val := range ProxyMap.m {
			if pm.protocol == HTTP_BLOCK && val.domain == pm.domain {
				lprintf(1, "[ERROR] check conf(HTTP) domain(%s) \n", pm.domain)
				os.Exit(1)
			} else if pm.protocol == STREAM_BLOCK && val.lPort == pm.lPort {
				lprintf(1, "[ERROR] check conf(TCP) port(%d) \n", val.lPort)
				os.Exit(1)
			}
		}

		ProxyMap.m[key] = pm

		lprintf(4, "[INFO] Proxy Info protocol(%s), domain(%s), lport(%s), tServer(%s), tPort(%s) \n", idx[0], idx[1], idx[2], idx[3], idx[4])
	}

	return Idle_t.MODE
}

func init_basic_data(fname string) {

	//about captcha
	captcha_m = make(map[int]types.ClientInfo)
	timer_off_seq = make(chan int, 1)
	timer_off_seq <- -1

	//slowread
	Ngxconf.Domain_m = make(map[string]types.Dominfo)
	Slowread = Slowread_s{0, 0, ""} //ttl,size,blocktime?

	//cache dir 	//cache clear
	v, r := cls.GetTokenValue("CACHE_DIR", fname)
	if r != cls.CONF_ERR {
		Idle_t.CACHE_DIR = v
	} else {
		lprintf(1, "[ERROR] not found CACHE_DIR in smartidle.ini")
		os.Exit(1)
		//Idle_t.CACHE_DIR = ""
	}

	//nginx path
	v, r = cls.GetTokenValue("NGINX_PATH", fname)
	if r != cls.CONF_ERR {
		Idle_t.NGX_PATH = v
	} else {
		Idle_t.NGX_PATH = ""
	}
	slash := strings.Index(fname, "smartidle")
	if Idle_t.NGX_PATH == "" {
		Idle_t.NGX_PATH = fname[:slash] + "nginx"
	}
	Idle_t.IDLE_DIR = fname[:slash] + "smartidle"

	//about captcha
	Idle_t.Imgpath = Idle_t.IDLE_DIR + "/image.gif"

	//auto ngx conf with sphere
	v, r = cls.GetTokenValue("AUTO_CONF", fname)
	if r != cls.CONF_ERR {
		Idle_t.AUTO_CONF = v
	} else {
		Idle_t.AUTO_CONF = ""
	}

	v, r = cls.GetTokenValue("MAP_TTL", fname)
	if r != cls.CONF_ERR {
		Idle_t.MAP_TTL, _ = strconv.Atoi(v)
	} else {
		Idle_t.MAP_TTL = 0
	}

	v, r = cls.GetTokenValue("CERT", fname)
	if r != cls.CONF_ERR {
		Idle_t.CERT_PATH = v
	} else {
		lprintf(1, "[ERROR] Check the certification file path")
		os.Exit(1)
	}

	v, r = cls.GetTokenValue("CHECK_HOST_CHANGE", fname)
	if r != cls.CONF_ERR {
		tmp := strings.Split(v, ",")
		intv, _ := strconv.Atoi(strings.TrimSpace(tmp[0]))
		Idle_t.AGENT_PORT = strings.TrimSpace(tmp[1])

		go mornitor_agent_file(intv, strings.TrimSpace(tmp[2]), strings.TrimSpace(tmp[3]))
	} else {
		lprintf(1, "[ERROR] Check the smartagent scale file path")
		os.Exit(1)
	}

	//	v, r = cls.GetTokenValue("MYIP_PORT", fname)
	//	if r != cls.CONF_ERR {
	//	Idle_t.Port_myip = strings.TrimSpace(v)

	//		go myip(Idle_t.Port_myip)
	//}

	lprintf(4, "[INFO] *** SMARTIDLE PATH (%s)\n", Idle_t.IDLE_DIR)
	lprintf(4, "[INFO] *** NGINX PATH (%s)\n", Idle_t.NGX_PATH)
	lprintf(4, "[INFO] *** CACHE_DIR (%s)\n", Idle_t.CACHE_DIR)
	lprintf(4, "[INFO] *** MAP_TTL (%d)\n", Idle_t.MAP_TTL)
	lprintf(4, "[INFO] *** CERT_PATH (%s)\n", Idle_t.CERT_PATH)

	lprintf(4, "[INFO] cls eth card(%s) \n", cls.Eth_card)

	// network card id
	card_idx := cls.Eth_card[3:]
	card_num, err := strconv.Atoi(card_idx)
	if err != nil || card_num > 255 {
		lprintf(1, "[FAIL] can not find card number (%s)", card_idx)
		return
	}
	//Idle_t.TargetIP = fmt.Sprintf("127.0.%d.2", card_num)
	Idle_t.TargetIP = "127.0.0.2"
	lprintf(4, "[INFO] *** TARGET NGINX IP (%s)", Idle_t.TargetIP)

	//set public ip
	//Idle_t.PublicIP = getpubip()

	//test ring
	/*fqdn := "aaa.nomqsw.com"
	FqdnMap.m[fqdn] = new(Ips_s)
	FqdnMap.m[fqdn].IpsInfo = test_ring(fqdn)
	fqdn = "bbb.nomqsw.com"
	FqdnMap.m[fqdn] = new(Ips_s)
	FqdnMap.m[fqdn].IpsInfo = test_ring(fqdn)
	*/
	//Idle_t.iListenIP = binary.LittleEndian.Uint32(net.ParseIP(cls.ListenIP)[12:16])
	//Idle_t.iTargetIP = binary.LittleEndian.Uint32(net.ParseIP(Idle_t.TargetIP)[12:16])

	//port
	//	details := "cannot find that port in the nginx config"
	//	agent_sendErr(ERR_PORT_NONE, "192.168.59.50:49985", "", "9696", details)

	//no host
	//	details = "cannot serve the host(not serviced fqdn)"
	//	agent_sendErr(ERR_HOST_NONE, "192.168.59.50:49986", "no.host.com", "9595", details)

	//pkt문제
	//	details := "header didnot have host"
	//	agent_sendErr(ERR_HOST_PKT, "192.168.59.50:49987", "", "1080", details)
	//	details = "content length is not number"
	//	agent_sendErr(ERR_HOST_PKT, "192.168.59.50:49988", "boys.realprimedom1.net", "1128", details)

	/*//captcha image
	details := "image file open failed"
	agent_sendErr(ERR_FILE_CAPIMG, "", "", "", details)
	details = "writing to image file failed"
	agent_sendErr(ERR_FILE_CAPIMG, "", "", "", details)
	*/
	//ngx
	//	details = "NGINX cannot write - " + "127.0.0.2:1080: connection refused"
	//agent_sendErr(ERR_NGX_WR, "192.168.59.50:49985", "flash.realprimedom1.info", "1080", details)
	////details = "PID did not changed"
	//agent_sendErr(ERR_NGX_RELOAD, "", "", "", details)
	//details = "Reload run command fail"
	//agent_sendErr(ERR_NGX_RELOAD, "", "", "", details)
	//details = "file copy failed - " + "from(/smartagent/Plugins/eth0/nginx/conf/httpblk.conf.bak)->to(/smartagent/Plugins/eth0/nginx/conf/httpblk.conf)"
	//agent_sendErr(ERR_NGX_ROLLB, "", "", "", details)
	//details = "nginx config file read error"
	//agent_sendErr(ERR_NGX_CONF, "", "", "", details)

}

func App_page() []cls.AppPages {
	// smartNginx page setting
	lprintf(4, "[INFO] paging start \n")

	//var get_pkt func(h http.ResponseWriter, r *http.Request, ps httprouter.Params) = cls.AppPages.Ufc

	// Site set 메인 페이지
	pages := []cls.AppPages{

		// captcha
		{cls.GET, "/", Response_first, nil},
		{cls.GET, "/req_captcha", Response_first, nil}, //request_html
		{cls.GET, "/req_captcha/", Response_first, nil},
		{cls.GET, "/req_captcha/:client_img", Response_image, nil}, //request_image
		{cls.POST, "/ans_captcha", Check_form, nil},                //upload_form

		{cls.GET, "/cache_clear", cache_clear, nil},

		//agent랑 통신
		//		{cls.POST, "/SOMETHING", from_agent, nil}, //agent에서 주는 uri 확인해야함

		//standalone ver
		{cls.GET, "/conf_modify", ngx_direct_modify, nil},
		{cls.POST, "/conf_modify_done", ngx_modify_done, nil},

		//station이랑 통신(auto)
		{cls.GET, "/ngx_conf_req", ngx_conf_resp, nil},
		{cls.POST, "/ngx_reload", ngx_new_conf, nil},
	}

	return pages
}

func App_main(ad *cls.AppdataInfo) int {
	//	lprintf(4, "[INFO] app main called (%d, %d)", ad.NState, ad.Service)

	switch ad.NState {
	case cls.CK_TIMER:
		return 0
	case cls.CO_SERVER:
		lprintf(4, "[INFO] CO_SERVER, Not Implemented")

		return 0

	case cls.CK_CLIENT:
		lprintf(4, "[INFO] CK_CLIENT, Not Implemented")

		return 0

	case cls.RD_CLIENT:
		lprintf(4, "[INFO] RD_CLIENT ")
		//	lprintf(4, "[INFO] TCP data (%s)", string(ad.Client.Rbuf))
		if ad.Service == cls.UDP_ECHO {
			ad.ResBool = true // client로 응답
			//	ad.Client.Sbuf = ad.Server.Rbuf
			//	ad.Client.Slen = ad.Server.Tlen
			lprintf(4, "[INFO] UDP data (%s)", string(ad.Client.Rbuf))
			if req_client_url(string(ad.Client.Rbuf)) < 0 {
				//	lprintf(4, "[FAIL]  failed.")
				return -1
			}
		} else if ad.Service == cls.TCP_HTTP { //TCP_AGENT? //get from agent
			ad.ResBool = false // forward 설정(false가 on, true는 client로 응답)

			//	lprintf(4, "[INFO] TCP data (%s)", string(ad.Client.Rbuf))

			recv_data := bytes.Trim(ad.Client.Rbuf, "\x00")

			ad.Server.Sbuf = recv_data
			//ad.Server.Slen = len(recv_data)

			return 0

		}
		return 0

	case cls.CK_SERVER:
		lprintf(4, "[INFO] CK_SERVER, Not Implemented")
		/*hlen, clen, ret := cls.GetHtmlLength(ad.Server.Rheader)
		if ret == cls.CONF_ERR { // header is zero, somthing wrong
			lprintf(1, "[FAIL] can not parse http header")
			return (-1)
		}
		ad.Server.Tlen = hlen + clen // total len = header + content*/

		return 0

	case cls.RD_SERVER:
		lprintf(4, "[INFO] RD_SERVER, Not Implemented")
		ad.ResBool = true // RD_CLIENT에서 forward로 보냈음. response 필요x  false하면 for문으로 무한보내짐
		//lprintf(4, "data from fwd server(%s)", ad.Server.Rbuf[:200])
		ad.Client.Sbuf = ad.Server.Rbuf
		ad.Client.Slen = len(ad.Server.Rbuf)

		return 0

	default:
		lprintf(1, "[FAIL] Cannot connect to the Server ")
		return (-1)
	}

	return 0
}

func app_handle(packet, clientIp string, tp_type int) (RESULT, string) {

	return do_map(packet, clientIp, tp_type)

}

func test_xml() {

	test_gset_sphere_data()

	/*file, _ := os.Create("testconf.txt")
	defer file.Close()
	fmt.Fprint(file, str)*/
}

func test_gset_sphere_data() {
	//xml, err := ioutil.ReadFile("testxml.txt")
	//if err != nil {
	//	panic(err)
	//}
	//	gset_sphere_data("tcp.nomqsw.com", "")
}
