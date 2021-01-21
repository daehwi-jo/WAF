package smartidle

import (
	"encoding/xml"
	"os"
	"strings"
	"time"

	"charlie/i0.0.2/cls"
	types "smartidle/smartidle-i2.0.1/model/smartidle"
	//	"github.com/julienschmidt/httprouter"
)

/*
type Conf_s struct {
	User        string   `xml:"user"`
	Worker_proc string   `xml:"worker_processes"`
	Error_log   []string `xml:"error_log"`

	Domain string `xml:"domain"`
	Status string `xml:"status"`

	Cache []Cache_s `xml:"cacheinfo"`

	Http      Http_s        `xml:"http"`
	Stream    Stream_s      `xml:"stream"`
	Ipsinfo   []Ipsinfo_s   `xml:"ipsinfo"`
	WebFilter []WebFilter_s `xml:"webfilter"`

	Dom_ver       string `xml:"domainversion"`
	Ips_ver       string `xml:"ipsversion"`
	WebFilter_ver string `xml:"webfilterversion"`

	Events Event_s `xml:"events"`
}
*/

func printXml(mainxml types.Main_xml) {
	for _, xml := range mainxml.Conf {
		lprintf(4, "[INFO] idle get nginx conf xml type \n")
		lprintf(4, "[INFO] xml user(%s) \n", xml.User)
		lprintf(4, "[INFO] xml worker proc(%s) \n", xml.Worker_proc)

		for _, elog := range xml.Error_log {
			lprintf(4, "[INFO] xml error log(%s) \n", elog)
		}

		lprintf(4, "[INFO] xml Domain(%s) \n", xml.Domain)
		lprintf(4, "[INFO] xml Status(%s) \n", xml.Status)
		lprintf(4, "[INFO] xml Dom ver(%s) \n", xml.Dom_ver)
		lprintf(4, "[INFO] xml Ips ver(%s) \n", xml.Ips_ver)
		//lprintf(4, "[INFO] xml WebFilter ver(%s) \n", xml.WebFilter_ver)

		for _, httpBlock := range xml.Http.Server {
			lprintf(4, "[INFO]--------------------\n")
			lprintf(4, "[INFO] http block serverName(%s) \n", httpBlock.Server_name)
			lprintf(4, "[INFO] http block captcha(%s) \n", httpBlock.Captcha)
			lprintf(4, "[INFO] http block cache(%s) \n", httpBlock.Cache)
			lprintf(4, "[INFO] http block auto cache(%s) \n", httpBlock.Autocache)
			lprintf(4, "[INFO] http block file ctl(%s) \n", httpBlock.Filectl)
			lprintf(4, "[INFO] http block injection(%s) \n", httpBlock.Injection)
		}

		for _, cache := range xml.Cache {
			lprintf(4, "[INFO]--------------------\n")
			lprintf(4, "[INFO] xml cache host(%s) \n", cache.Host)
			lprintf(4, "[INFO] xml cache size(%s) \n", cache.CacheSize)
			lprintf(4, "[INFO] xml cache key memory(%s) \n", cache.KeyMemory)
			lprintf(4, "[INFO] xml cache inactive(%s) \n", cache.Inactive)
		}

		for _, ips := range xml.Ipsinfo {
			lprintf(4, "[INFO]--------------------\n")
			lprintf(4, "[INFO] xml ips serverName(%s) \n", ips.Server_name)
			lprintf(4, "[INFO] xml ips client captcha use(%d) \n", ips.CaptchaUse)
			lprintf(4, "[INFO] xml ips fdqn captcha use(%d) \n", ips.NginxCaptchaYN)
			lprintf(4, "[INFO] xml ips def use(%d) \n", ips.DefUse)
			lprintf(4, "[INFO] xml ips plus on type(%s) \n", ips.PlusonType)
			lprintf(4, "[INFO] xml ips plus on ip(%s) \n", ips.PlusonDestIp)
			lprintf(4, "[INFO] xml ips plus on port(%s) \n", ips.PlusonDestPort)
			lprintf(4, "[INFO] xml ips http cmd(%s) \n", ips.HttpCmd)
			lprintf(4, "[INFO] xml ips http cnt(%d) \n", ips.HttpCnt)
			lprintf(4, "[INFO] xml ips http except(%s) \n", ips.HttpExcept)
			lprintf(4, "[INFO] xml ips http filter(%s) \n", ips.HttpFilter)
			lprintf(4, "[INFO] xml ips http maxSize(%d) \n", ips.HttpMaxSize)
			lprintf(4, "[INFO] xml ips http period(%d) \n", ips.HttpPeriod)

			for _, wf := range ips.WebFilter {
				lprintf(4, "[INFO]--------------------\n")
				lprintf(4, "[INFO] xml http web filter key(%s) \n", wf.Header)
				lprintf(4, "[INFO] xml http web filter value(%s) \n", wf.Value)
				lprintf(4, "[INFO] xml http web filter case(%d) \n", wf.Case)
			}
		}

		/*
			for _, wfilter := range xml.WebFilter {
				lprintf(4, "[INFO]--------------------\n")
				lprintf(4, "[INFO] xml web filter serverName(%s) \n", wfilter.Server_name)
				lprintf(4, "[INFO] xml web filter captcha use(%d) \n", wfilter.CaptchaUse)
				lprintf(4, "[INFO] xml web filter def use(%d) \n", wfilter.DefUse)
				lprintf(4, "[INFO] xml web header(%s) \n", wfilter.Header)
				lprintf(4, "[INFO] xml web value(%s) \n", wfilter.Value)
				lprintf(4, "[INFO] xml web action(%s) \n", wfilter.Action)
				lprintf(4, "[INFO] xml web case(%d) \n", wfilter.Case)
				lprintf(4, "[INFO] xml web condition(%s) \n", wfilter.Condition)
				lprintf(4, "[INFO] xml web type(%s) \n", wfilter.Type)
			}
		*/

	}
}

func converter(xml_str, domver, ipsver, wfver string) RESULT { //xml to structure type

	//xml 구조체에 저장
	var mainxml types.Main_xml
	xml.Unmarshal([]byte(xml_str), &mainxml)

	/*
		if len(xml_str) < 200 {
			lprintf(4, "xml(%s)", xml_str)
		}
		lprintf(4, "xml(%s)", xml_str)
	*/

	lprintf(4, "[INFO] sphere get xml data(%v) \n", mainxml)
	printXml(mainxml)

	if strings.Index(xml_str, "Internal Server Error") > 0 {
		lprintf(4, "[INFO] xml msg is (Internal Server Error) from the sphere")
		return IGNORE
	}

	var fPath string
	for i := 0; i < len(mainxml.Conf); i++ { //conf 개수 만큼 돌아야함
		conf := mainxml.Conf[i]

		// domain 이름으로 cache path에 dir이 없을경우 생성
		fPath = Idle_t.CACHE_DIR + "/" + conf.Domain
		if !FileExist(fPath) {
			// file mode is drwxr-x---
			if err := os.MkdirAll(fPath, 0750); err != nil {
				lprintf(1, "[ERROR] cache dir(%s) make error(%s)\n", fPath, err.Error())
			}
		}

		//cnt++
		if conf.Status != "OK" || conf.Domain == "" {
			lprintf(4, "[INFO] conf Domain(%s), Status(%s) \n", conf.Domain, conf.Status)
			if conf.Status == "not changed" {
				return IGNORE
			}

			if conf.Status == "no data" {
				return REPORT
			}
			if conf.Status == "error" {
				return FAILURE
			}
			return IGNORE
		}
		//lprintf(4, "xml(%s)", xml_str)
		if conf.Domain == "" && conf.Status == "OK" {
			lprintf(1, "[WARN] The conf has not 'domain' in the xml (But <status> said `OK`)")
			return FAILURE
		}

		lprintf(4, "domver(%s),confdomver(%s)", domver, conf.Dom_ver)

		if domver == conf.Dom_ver {

			if ipsver != conf.Ips_ver {
				//return IGNORE
				lprintf(4, "[INFO] Ips info set.")
				insert_ipsmap(conf.Domain, conf.Ipsinfo)
			}

			/*
				if wfver != conf.WebFilter_ver {
					lprintf(4, "[INFO] WebFilter info set.")
					insert_wfmap(conf.Domain, conf.WebFilter)
				}
			*/

			lprintf(4, "[INFO] Only Ips info set.")
			return IGNORE
		}

		//	lprintf(4, "xml(%s)", xml_str)

		insert_confmap(conf, 0)
		insert_ipsmap(conf.Domain, conf.Ipsinfo)
		//insert_wfmap(conf.Domain, conf.WebFilter)
	}

	lprintf(4, "[INFO] convert xml success \n")

	return SUCCESS
}

/*
func insert_wfmap(domain string, xmlwf []types.WebFilter_s) {

	if len(xmlwf) == 0 {
		lprintf(4, "[INFO] no webFilter info.")
		return
	}

	var temp string

	FqdnMap.Lock()
	for idx := 0; idx < len(xmlwf); idx++ {
		wfinfo := xmlwf[idx]

		if temp != wfinfo.Server_name {
			FqdnMap.m[wfinfo.Server_name].Wf = nil
			temp = wfinfo.Server_name
		}

		var newinfo WebFilter
		newinfo.key = wfinfo.Header
		newinfo.value = wfinfo.Value
		newinfo.wCase = wfinfo.Case
		newinfo.defUse = wfinfo.DefUse
		newinfo.captchaUse = wfinfo.CaptchaUse

		lprintf(4, "[INFO] web(%s) filter info header(%s), value(%s), condition(%s), action(%s), case(%d) \n", wfinfo.Server_name, wfinfo.Header, wfinfo.Value, wfinfo.Condition, wfinfo.Action, wfinfo.Case)

		/*
			switch wfinfo.FilterType {
			case 1: // like
				if wfinfo.Action == "A" {
					newinfo.FilterType = 1 // 포함하지 않으면 drop, 있어야 pass
				} else {
					newinfo.FilterType = 2 // 포함하면 drop, 없어야 pass
				}
			case 2: // not like
				if wfinfo.Action == "A" {
					newinfo.FilterType = 2
				} else {
					newinfo.FilterType = 1
				}
			case 3: // getter than
				if wfinfo.Action == "A" {
					newinfo.FilterType = 4 // filter가 작으면 drop
				} else {
					newinfo.FilterType = 3 // filter가 크면 drop
				}
			case 4: // less than
				if wfinfo.Action == "A" {
					newinfo.FilterType = 3
				} else {
					newinfo.FilterType = 4
				}
			}

		FqdnMap.m[wfinfo.Server_name].Wf = append(FqdnMap.m[wfinfo.Server_name].Wf, newinfo)
	}
	FqdnMap.Unlock()
	print_wf()
}
*/

func insert_ipsmap(domain string, xmlips []types.Ipsinfo_s) {

	if len(xmlips) == 0 {
		lprintf(4, "[INFO] no IpsInfo.")
		return
	}

	//inform rtimer done to change rules
	FqdnMap.Lock()
	for key, ips := range FqdnMap.m {

		if strings.Contains(key, domain) {
			if ips.IpsInfo.conCnt != nil {
				ips.IpsInfo.done <- true
				close(ips.IpsInfo.done)
			}
			delete(FqdnMap.m, key)
		}
		//	close(ips.IpsInfo.gotcha)
		//	close(ips.IpsInfo.tcntOver)
	}

	//initialize the whole Map
	//var empty map[string]*IpsInfo_s
	//FqdnMap.m = empty

	//lprintf(4, "bbbbbbbbbbbbbbbb")
	for idx := 0; idx < len(xmlips); idx++ {
		ipsinfo := xmlips[idx]

		//lprintf(4, "aaaaaaaaaaaaaaaa")
		var newinfo IpsInfo_s

		newinfo.sname = ipsinfo.Server_name
		newinfo.id = ipsinfo.Server_id
		newinfo.cnt = ipsinfo.HttpCnt
		newinfo.period = ipsinfo.HttpPeriod
		newinfo.maxsize = ipsinfo.HttpMaxSize
		newinfo.defUse = ipsinfo.DefUse
		//newinfo.defUse = 0
		newinfo.captchaUse = ipsinfo.CaptchaUse
		newinfo.plusonType = ipsinfo.PlusonType
		newinfo.plusonIp = ipsinfo.PlusonDestIp
		newinfo.plusonPort = ipsinfo.PlusonDestPort

		// ips webfillter
		for w := 0; w < len(ipsinfo.WebFilter); w++ {
			hwf := ipsinfo.WebFilter[w]

			var wf WebFilter
			wf.key = hwf.Header
			wf.value = hwf.Value
			wf.wCase = hwf.Case

			newinfo.Wf = append(newinfo.Wf, wf)
		}

		if newinfo.period > 0 {
			newinfo.done = make(chan bool)
			//newinfo.tcntOver = make(chan RESULT)
			//	newinfo.gotcha = make(chan bool)
		}

		//newinfo.expList = ipsinfo.HttpExcept
		tmp := strings.Split(ipsinfo.HttpExcept, ",")
		newinfo.except = make([]string, len(tmp))
		for i := 0; i < len(tmp); i++ {
			newinfo.except[i] = strings.TrimSpace(tmp[i])
		}

		newinfo.cmdList = ipsinfo.HttpCmd
		/*tmp = strings.Split(ipsinfo.HttpCmd, ",")
		for i := 0; i < len(tmp); i++ {
			newinfo.cmd[i] = strings.TrimSpace(tmp[i])
		}*/

		tmp = strings.Split(ipsinfo.HttpFilter, ",")
		newinfo.filter = make([]string, len(tmp))
		for i := 0; i < len(tmp); i++ {
			newinfo.filter[i] = strings.TrimSpace(tmp[i])
		}

		//	FqdnMap.Lock()
		FqdnMap.m[ipsinfo.Server_name] = new(Ips_s)
		FqdnMap.m[ipsinfo.Server_name].IpsInfo = newinfo
		//FqdnMap.Unlock()

	}
	FqdnMap.Unlock()
	print_ips()
}

func insert_confmap(conf types.Conf_s, tabcnt int) {

	var dominfo types.Dominfo

	dom := conf.Domain

	dominfo.Dom_ver = conf.Dom_ver
	dominfo.Ips_ver = conf.Ips_ver
	//dominfo.Wf_ver = conf.WebFilter_ver
	dominfo.Intime = time.Now()
	dominfo.Status = "positive"

	// cache dir 체크
	if len(conf.Cache) > 0 {
		filePath := Idle_t.CACHE_DIR + "/" + cls.Eth_card + "/" + dom
		lprintf(4, "[INFO] check cache dir(%s) stat \n", filePath)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			os.MkdirAll(filePath, 0750)
		}
	}

	//lprintf(4, "[INFO] cache write(%d) \n", len(conf.Cache))
	for i := 0; i < len(conf.Cache); i++ {
		if len(conf.Cache[i].CacheSize) > 0 && conf.Cache[i].CacheSize != "0" {
			//dominfo.Blk_http += "proxy_cache_path /" + dom + "/" + conf.Cache[i].Host + " levels=1:2 keys_zone=" + conf.Cache[i].Host + "." + dom + ":10m max_size=" + conf.Cache[i].CacheSize + "m " + "inactive=1h;\n"
			dominfo.Blk_http += "proxy_cache_path /" + dom + "/" + conf.Cache[i].Host + " levels=1:2 keys_zone=" + conf.Cache[i].Host + "." + dom + ":" + conf.Cache[i].KeyMemory + "m max_size=" + conf.Cache[i].CacheSize + "m inactive=" + conf.Cache[i].Inactive + "h;\n"
		}
	}

	dominfo.Blk_http += "\n"
	/*
		if conf.Cache != "" && conf.Cache != "0" {

			lprintf(4, "[INFO] cache write \n")

			dominfo.Blk_http = "proxy_cache_path /" + dom + " levels=1:2 keys_zone=" + dom + ":10m max_size=" + conf.Cache + "m " + "inactive=1h;\n\n"
		}
	*/

	http := write_inside(conf.Http.Server, conf.Http.Upstream, dom, tabcnt, 0)
	if http == "" {
		dominfo.Blk_http = ""
	} else {
		dominfo.Blk_http += http
	}
	dominfo.Blk_str = write_inside(conf.Stream.Server, conf.Stream.Upstream, dom, tabcnt, 1)

	//map에 저장
	Ngxconf.Lock()
	Ngxconf.Domain_m[dom] = dominfo
	Ngxconf.Unlock()

	lprintf(4, "[INFO] insert confmap success \n")

}

func write_inside(svr []types.Server_s, upst []types.Upstream_s, dom string, tabcnt, isstr int) string {

	var str string

	for index_srv := 0; index_srv < len(svr); index_srv++ {
		server := svr[index_srv]

		str += write_tab(tabcnt) + "server {\n"

		tabcnt++

		for index_lis := 0; index_lis < len(server.Listen); index_lis++ {
			listen := server.Listen[index_lis]

			//https ver
			i := strings.Index(listen, "ssl")
			if i != -1 {
				str += "\n" + write_tab(tabcnt) + "listen 127.0.0.2:" + listen[:i-1] + "; #" + listen[i:] + "\n"
			} else {
				str += "\n" + write_tab(tabcnt) + "listen 127.0.0.2:" + listen + ";\n"
			}
		}

		if server.Cache == "1" {
			// 기존 cahce를 domain 단위로 관리하다가, host 단위로 관리 하는걸로 변경되면서 proxy_cache(key)를 domain에서 fqdn으로 변경
			//str += write_tab(tabcnt) + "proxy_cache " + dom + ";\n"
			str += write_tab(tabcnt) + "proxy_cache " + server.Server_name + ";\n"
		}

		/*
			동일한 요청이 들어왔을 경우 service server의 응답이 오기 전
			패킷을 보내지 않는 기능
		*/
		if server.Filectl != "0" && server.Filectl != "" {
			str += write_tab(tabcnt) + "same_req_limit on;\n"
			str += write_tab(tabcnt) + "same_file_req_limit " + server.Filectl + "k;\n"
		}

		/*
			nginx에서 관리하는 cache 데이터를 갱신
		*/
		if server.Autocache == "1" {
			str += write_tab(tabcnt) + "autocache on;\n"
		}
		if server.Injection != "" && server.Injection != "0" {
			str += "\n"
			str += write_tab(tabcnt) + "SecRulesEnabled; DeniedUrl '/50x.html'; CheckRule '$SQL >= " + server.Injection + "' BLOCK; error_log logs/naxsi.log;\n"
			str += "\n"
		}

		if server.Proxy_pass != "" {
			str += write_tab(tabcnt) + "proxy_pass " + server.Proxy_pass + ";\n"
		}
		if server.Server_name != "" {
			var remark string = ""
			if isstr == 1 {
				remark = "#"
			}
			str += write_tab(tabcnt) + remark + "server_name " + server.Server_name + ";\n"
			if isstr != 1 {
				//str += write_tab(tabcnt) + "proxy_set_header Host " + server.Server_name + ";\n"
			}
		}

		//		nginx에서 사용하던 captcha 기능은 idle에서 처리하도록 변경
		if server.Captcha == "1" {
			str += write_tab(tabcnt) + "captcha on;\n"
		}

		/*
			lprintf(4, "[INFO] 111111111111 \n")
			FqdnMap.Lock()
			fqdn, exist := FqdnMap.m[server.Server_name]
			if exist {

				lprintf(4, "[INFO] 122222222222222 \n")

				if server.Captcha == "1" {
					fqdn.captcha = true
				} else {
					fqdn.captcha = false
				}

				FqdnMap.m[server.Server_name] = fqdn
			}
			FqdnMap.Unlock()
		*/

		if server.Ssl_certi != "" {
			str += write_tab(tabcnt) + "#ssl_certificate " + server.Ssl_certi + ";\n"
		}
		if server.Ssl_sess_cache != "" {
			str += write_tab(tabcnt) + "#ssl_session_cache " + server.Ssl_sess_cache + ";\n"
		}
		if server.Ssl_certi_key != "" {
			str += write_tab(tabcnt) + "#ssl_certificate_key " + server.Ssl_certi_key + ";\n"
		}
		if server.Ssl_sess_timeout != "" {
			str += write_tab(tabcnt) + "#ssl_session_timeout " + server.Ssl_sess_timeout + ";\n"
		}
		if server.Ssl_ciphers != "" {
			str += write_tab(tabcnt) + "#ssl_ciphers " + server.Ssl_ciphers + ";\n"
		}

		for index_loc := 0; index_loc < len(server.Location); index_loc++ {
			loca := server.Location[index_loc]

			str += "\n" + write_tab(tabcnt) + "location "
			if loca.Name != "" {
				str += loca.Name + " { \n"
			}

			tabcnt++

			str += write_tab(tabcnt) + "proxy_http_version 1.1; \n"
			str += write_tab(tabcnt) + "proxy_set_header Connection \"keep-alive\"; \n"
			str += write_tab(tabcnt) + "proxy_set_header Host " + server.Server_name + ";\n"

			if loca.Index != "" {
				// test
				str += write_tab(tabcnt) + "index " + loca.Index + ";\n"
			}

			for index_pp := 0; index_pp < len(loca.Proxy_pass); index_pp++ {
				str += write_tab(tabcnt) + "proxy_pass " + loca.Proxy_pass[index_pp] + ";\n"
			}

			if loca.Root != "" {
				// test
				str += write_tab(tabcnt) + "root " + loca.Root + ";\n"
			}
			tabcnt--
			str += write_tab(tabcnt) + "}\n"

		}
		tabcnt--
		str += "\n#port open\n"
		str += write_tab(tabcnt) + "}\n\n"

	}
	//lprintf(4, "confstr2:(%s)\n", conf_str)
	for index_upst := 0; index_upst < len(upst); index_upst++ {
		upstream := upst[index_upst]

		str += "\n" + write_tab(tabcnt) + "upstream "
		if upstream.Name != "" {
			str += upstream.Name + " { \n"
		}

		tabcnt++

		if upstream.Keepalive != "" {
			//str += write_tab(tabcnt) + "keepalive " + upstream.Keepalive + ";\n"
			str += write_tab(tabcnt) + "keepalive " + "1500" + ";\n" // nginx test 용 keepalive
		}
		if upstream.Server != "" {
			tmp := strings.Split(upstream.Server, ",")
			for i := 0; i < len(tmp); i++ {
				//str += write_tab(tabcnt) + "server " + tmp[i] + ";\n"
				str += write_tab(tabcnt) + "server " + tmp[i] + ";\n"
			}
			//	str += write_tab(tabcnt) + "server " + upstream.Server + ";\n"
		}
		tabcnt--
		str += write_tab(tabcnt) + "}\n"
	}

	return str
}

func write_tab(cnt int) string {
	var ret string

	for i := 0; i < cnt; i++ {
		ret += "\t"
	}
	return ret
}
