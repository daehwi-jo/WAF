package smartidle

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"charlie/i0.0.2/cls"
	"github.com/julienschmidt/httprouter"
	types "smartidle/smartidle-i2.0.1/model/smartidle"
)

/*
var timetodel chan bool = make(chan bool)
var pass_port chan int = make(chan int)*/

//var Timetodel chan bool
//var pass_port chan int

func ngx_direct_modify(h http.ResponseWriter, r *http.Request, ps httprouter.Params) { //auto conf
	//	str_conf := ngx_read_conf()
	var tmpl = types.Templ{}
	tmpl.Str_conf = ngx_read_conf()

	cls.Renderer.HTML(h, http.StatusOK, "smartidle/ngx_modify_conf", tmpl)
}

func ngx_modify_done(h http.ResponseWriter, r *http.Request, ps httprouter.Params) { //auto conf

	var tmpl = types.Templ{}
	tmpl.Success_flag = "Success" //success

	new_conf := r.FormValue("ngx_config")
	//addrs := strings.Split(r.FormValue("ipaddrs"), "/")

	//tmpl.Str_conf = new_conf

	if change_conf(new_conf, "nginx.conf") < 0 { // change the old file to the new
		lprintf(1, "[NGINX] Changing the Conf file to the new failed")
		return
	}

	if ngx_reload() < 0 {
		lprintf(1, "[NGINX] Nginx Reload failed\n")
		tmpl.Success_flag = "Failure" //failure

		if rollback_conf("nginx.conf") < 0 {
			lprintf(1, "[NGINX] Nginx Rollback failed\n")
			tmpl.Success_flag = "Reload Failed, and also Rollback Failed.." //also rollback failure
		}
	}
	cls.Renderer.HTML(h, http.StatusOK, "smartidle/ngx_modify_result", tmpl)
}

func ngx_conf_resp(h http.ResponseWriter, r *http.Request, ps httprouter.Params) { //station에 nginx conf 주기 //auto conf

	cls.Renderer.Text(h, http.StatusOK, ngx_read_conf())
}

func ngx_new_conf(h http.ResponseWriter, r *http.Request, ps httprouter.Params) { //auto conf
	new_conf := r.FormValue("ngx_new_conf")

	h.Header().Add("success_flag", "Success") //success로 초기 setting

	if change_conf(new_conf, "nginx.conf") < 0 { // change the old file to the new
		lprintf(1, "[NGINX] Changing the Conf file to the new failed\n")
		h.Header().Set("success_flag", "Failure")
	} else {
		if ngx_reload() < 0 {
			lprintf(1, "[NGINX] Nginx Reload failed\n")
			h.Header().Set("success_flag", "Failure")

			if rollback_conf("nginx.conf") < 0 {
				lprintf(1, "[NGINX] Nginx Rollback failed\n")
				h.Header().Set("success_flag", "Reload Failed, and also Rollback Failed..") //also rollback failure
			}
		}
	}

	cls.Renderer.Text(h, http.StatusOK, "")
}

/*func change_file(conf_str string) int {
	if copy_file(Idle_t.NGX_PATH+"/conf/nginx.conf", Idle_t.NGX_PATH+"/conf/bak_nginx.conf") != nil {
		lprintf(4, "[FAIL] conf file backup failed: from(%s)->to(%s)", Idle_t.NGX_PATH+"/conf/nginx.conf", Idle_t.NGX_PATH+"/conf/bak_nginx.conf")
		return -1
	}

	os.Remove(Idle_t.NGX_PATH + "/conf/nginx.conf")

	file_new, _ := os.Create(Idle_t.NGX_PATH + "/conf/nginx.conf")
	defer file_new.Close()

	fmt.Fprint(file_new, conf_str)

	lprintf(4, "[INFO] Changing file done successfully.\n")
	return 0
}*/

func change_conf(newdata string, fname string) int {

	//alse store new data
	file_new, _ := os.Create(Idle_t.NGX_PATH + "/conf/" + fname + ".new")
	defer file_new.Close()

	fmt.Fprint(file_new, newdata)

	//save the original file as backup
	if copy_file(Idle_t.NGX_PATH+"/conf/"+fname, Idle_t.NGX_PATH+"/conf/"+fname+".bak") != nil {
		lprintf(1, "[NGINX] conf file backup failed: from(%s)->to(%s)", fname, fname+".bak")

		//details := "conf file backup failed - " + "from(" + fname + ")->to(" + fname + ".bak)"
		//agent_sendErr(ERR_NGX_CONF, "", "", "", details)

		return -1
	}

	os.Remove(Idle_t.NGX_PATH + "/conf/" + fname)

	file_ori, _ := os.Create(Idle_t.NGX_PATH + "/conf/" + fname)
	defer file_ori.Close()

	fmt.Fprint(file_ori, newdata)

	lprintf(4, "[NGINX] Changing conf(%s) file done successfully.\n", fname)

	return 0
}

func ngx_reload() RESULT {

	ngxpid := ngx_pid()
	lprintf(4, "[NGINX] BEFORE worker pid (%s)", ngxpid)

	cmd := fmt.Sprintf("%s/sbin/nginx -s reload -p %s -e %s", Idle_t.NGX_PATH, Idle_t.NGX_PATH, cls.Eth_card)
	//cmd := "/smartagent/Plugins/eth0/nginx/op-shell/reload.sh"
	lprintf(4, "[INFO] nginx reload cmd(%s)\n", cmd)

	//exe := exec.Command(Idle_t.NGX_PATH+"/sbin/nginx", "-s", "reload", "-p", Idle_t.NGX_PATH, "-e", cls.Eth_card)
	exe := exec.Command("/bin/bash", "-c", cmd)
	//if err := exe.Run(); err != nil {
	output, err := exe.CombinedOutput()
	if err != nil {
		lprintf(1, "[FAIL] Nginx Reload run command fail(%s), output(%s) \n", err.Error(), string(output))
		return FAILURE
	}

	go go_ngx_pid(ngxpid)
	//lprintf(4, "[NGINX] Current worker pid (%s)", ngx_pid())

	lprintf(4, "[NGINX] Reloading...")
	///smartagent/Plugins/eth0/nginx/sbin/nginx -t -p /smartagent/Plugins/eth0/nginx // conf file 검사하는 명령어

	return SUCCESS
}

func ngx_pid() string {
	list, err := exec.Command("/usr/bin/pgrep", "-fla", "nginx").Output()
	if err != nil {

		list, err = exec.Command("/usr/bin/pgrep", "-fl", "nginx").Output()
		if err != nil {
			lprintf(1, "[ERROR] NGINX run cmd output fail(%s) \n", err.Error())
			return ""
		}

	}
	outData := strings.TrimSpace(string(list))

	var pid string
	line := strings.Split(outData, "\n")
	for i := 0; i < len(line); i++ {
		if strings.Contains(line[i], "worker") {
			val := strings.Split(line[i], " ")
			pid = val[0]
			break
		}
	}
	if pid == "" {
		lprintf(1, "[ERROR] NGINX no worker process")
		return ""
	}

	return strings.TrimSpace(pid)
}
func go_ngx_pid(preid string) {
	time.Sleep(1 * time.Second)

	list, err := exec.Command("/usr/bin/pgrep", "-fla", "nginx").Output()
	if err != nil {

		list, err = exec.Command("/usr/bin/pgrep", "-fl", "nginx").Output()
		if err != nil {
			lprintf(1, "[ERROR] NGINX run cmd output fail(%s) \n", err.Error())
			return
		}

	}
	outData := strings.TrimSpace(string(list))

	var pid string
	line := strings.Split(outData, "\n")
	for i := 0; i < len(line); i++ {
		if strings.Contains(line[i], "worker") {
			val := strings.Split(line[i], " ")
			pid = val[0]
			break
		}
	}

	lprintf(4, "[NGINX] AFTER worker pid (%s)", pid)

	if pid == "" {
		lprintf(1, "[ERROR] NGINX no worker process")

		//details := "no worker process"
		//agent_sendErr(ERR_NGX_RELOAD, "", "", "", details)

		return
	}

	if strings.TrimSpace(pid) == preid {
		lprintf(1, "[NGINX] Reload Failed. PID did not changed.")

		//details := "PID did not changed"
		//agent_sendErr(ERR_NGX_RELOAD, "", "", "", details)

	} else {
		lprintf(4, "[NGINX] Reload Done Successfully!")
	}

	return
}

func rollback_conf(fname string) RESULT {

	os.Remove(Idle_t.NGX_PATH + "/conf/" + fname)

	file_origin, err := os.Open(Idle_t.NGX_PATH + "/conf/" + fname + ".bak")
	if err != nil {
		lprintf(1, "[NGINX] Conf file Rollback failed. There isn't original file(%s).\n", fname)

		//details := "There isn't original file - " + fname
		//agent_sendErr(ERR_NGX_ROLLB, "", "", "", details)

		return FAILURE
	}
	defer file_origin.Close()

	if copy_file(Idle_t.NGX_PATH+"/conf/"+fname+".bak", Idle_t.NGX_PATH+"/conf/"+fname) != nil {
		lprintf(1, "[NGINX]  Conf file Rollback copy failed: from(%s)->to(%s)", fname+".bak", fname)

		//details := "file copy failed - " + "from(" + fname + ".bak)->to(" + fname + ")"
		//agent_sendErr(ERR_NGX_ROLLB, "", "", "", details)

		return FAILURE
	}

	lprintf(4, "[NGINX] Conf file(%s) Rollback done successfully.\n", fname)
	return SUCCESS
}

func ngx_read_conf() string { //auto conf
	file, err := os.Open(Idle_t.NGX_PATH + "/conf/nginx.conf")
	if err != nil {
		lprintf(1, "[NGINX] Conf file open error\n")

		return ""
	}
	defer file.Close()

	fi, err := file.Stat()
	if err != nil {
		return ""
	}

	var str_conf = make([]byte, fi.Size())

	n, err := file.Read(str_conf)
	if err != nil {
		lprintf(1, "[NGINX] Conf file read error(%d byte)\n", n)
		return ""
	}

	//lprintf(4, "[INFO] Conf file read done(\n%s)\n", string(str_conf))

	return string(str_conf)
}

func setconf() RESULT {
	var http, str string

	Ngxconf.RLock()

	http = "#http block\n\n"
	for key, val := range Ngxconf.Domain_m {

		if val.Status == "negative" {
			continue
		}
		//	lprintf(4, "key(%s) write", key)

		if val.Blk_http == "" {
			continue
		}

		http += "#domain:" + key + "\n"
		http += val.Blk_http + "\n"
		http += "#domain end\n\n"
	}

	str = "#stream block\n\n"
	for key, val := range Ngxconf.Domain_m {

		if val.Status == "negative" {
			continue
		}

		if val.Blk_str == "" {
			continue
		}

		//lprintf(4, "domain write(%s),(%s)", key, val.Blk_str)
		str += "#domain:" + key + "\n"
		str += val.Blk_str + "\n"
		str += "#domain end\n\n"
	}

	Ngxconf.RUnlock()

	if change_conf(http, "httpblk.conf") < 0 {
		return FAILURE
	}
	if change_conf(str, "streamblk.conf") < 0 {
		return FAILURE
	}

	return SUCCESS
}

func ngx_conf_sync(xml_str, domain, domver, ipsver, wfver string, reload_flg bool) RESULT { //converting 'xml' to '.conf' file and making reload signal to the Nginx

	ret := converter(xml_str, domver, ipsver, wfver)
	lprintf(4, "ngx_conf_sync host(%s)", domain)

	if ret == FAILURE {
		lprintf(1, "[ERROR] Got <status> error code. Can not convert to the Map. Enrolled with 'negative'.domain")
		/*var dominfo types.Dominfo
		  dominfo.Intime = time.Now()
		  dominfo.Status = "negative"
		  dominfo.Blk_http = Ngxconf.Domain_m[domain].Blk_http
		  dominfo.Blk_str = Ngxconf.Domain_m[domain].Blk_str
		  dominfo.port */
		Ngxconf.Lock()
		dominfo, _ := Ngxconf.Domain_m[domain]

		dominfo.Intime = time.Now()
		dominfo.Status = "negative"
		Ngxconf.Domain_m[domain] = dominfo
		Ngxconf.Unlock()

		return IGNORE

	} else if ret == IGNORE {
		lprintf(4, "[INFO] Nothing to do with Nginx")
		return IGNORE
	} else if ret == REPORT {
		return REPORT
	}

	if reload_flg == false {
		lprintf(4, "[INFO] Nothing to do with Nginx, reload_flag false")
		return IGNORE
	}

	//http,stream block conf write
	if setconf() == FAILURE {
		lprintf(1, "[FAIL] Can not set block conf")

		return IGNORE
	}

	if ngx_reload() != SUCCESS {
		lprintf(1, "[FAIL] Nginx Reload failed\n")

		if rollback_conf("httpblk.conf") == FAILURE {
			lprintf(1, "[FAIL] httpblk Rollback failed\n")
		}
		if rollback_conf("streamblk.conf") == FAILURE {
			lprintf(1, "[FAIL] streamblk Rollback failed\n")
		}
	} else {

		//idle listen 다시
		load_conf(Idle_t.NGX_PATH + "/conf/httpblk.conf")
		load_conf(Idle_t.NGX_PATH + "/conf/streamblk.conf")

	}

	lprintf(4, "ngx_conf_sync success \n")
	return SUCCESS
}

func load_conf(fname string) {
	// smartNginx page setting
	lprintf(4, "[NGINX] Nginx Conf Load (%s)", fname)

	file, err := os.Open(fname)
	if err != nil {
		lprintf(1, "[ERROR] cannot open nginx config file (%s)", fname)

		//details := "cannot open nginx config file - " + fname
		//agent_sendErr(ERR_NGX_CONF, "", "", "", details)

		//lprintf(1,"[ERROR] Check the Conf file")
		os.Exit(1)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	mode := COMMON_BLOCK

	var dominfo types.Dominfo
	var domexist bool = true
	var dom string = ""
	var portinfo BlockInfo
	//	var pinfo []BlockInfo

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if domexist == false && dom != "" && strings.HasSuffix(line, " end") == false {
			if mode == HTTP_BLOCK {
				dominfo.Blk_http += line + "\n"
			} else if mode == STREAM_BLOCK {
				dominfo.Blk_str += line + "\n"
			}
		}

		if strings.HasPrefix(line, "#http") { // http block
			//lprintf(4, "[INFO] config find http block(%s)\n", line)
			mode = HTTP_BLOCK
		} else if strings.HasPrefix(line, "#stream") { // stream block
			//lprintf(4, "[INFO] config find stream block(%s)\n", line)
			mode = STREAM_BLOCK
		}

		// make port map
		if strings.HasPrefix(line, "listen ") {
			port := strings.TrimSpace(line[7:])
			iport := 0

			if strings.Contains(port, "ssl") {
				iport, _ = strconv.Atoi(port[:len(port)-6])

				portinfo.ssl = true
				portinfo.port = iport
				portinfo.block = mode
				//portinfo.close = make(chan bool)

			} else {
				iport, _ = strconv.Atoi(port[:len(port)-1])

				portinfo.ssl = false
				portinfo.port = iport
				portinfo.block = mode
			}

			//	lprintf(4, "[INFO] config find listen port (%s) -> (%d)\n", port, iport)
		}

		idx := strings.Index(line, "ssl_certificate ")
		if idx > 0 {
			crt := strings.TrimSpace(line[idx+16 : len(line)-1]) //might has '#' & ';'
			/*	if strings.Contains(crt, "ssl/") {
					idx = 4
				} else {
					idx = 0
				}
				portinfo.crt = Idle_t.CERT_PATH + "/" + crt[idx:]*/
			portinfo.crt = Idle_t.CERT_PATH + "/" + crt
		}
		idx = strings.Index(line, "ssl_certificate_key ")
		if idx > 0 {
			key := strings.TrimSpace(line[idx+20 : len(line)-1]) //might has '#' & ';'

			portinfo.key = Idle_t.CERT_PATH + "/" + key
		}

		if strings.Contains(line, "server_name ") {
			sname := strings.TrimSpace(line[12 : len(line)-1])
			//	lprintf(4, "[INFO] config find server name insert map (%s)\n", sname)
			portinfo.fqdn = sname
			portinfo.domain = dom

		}

		if strings.HasPrefix(line, "#domain:") {
			tmp := strings.Split(line, ":")
			dom = tmp[1]

			Ngxconf.RLock()
			dominfo, domexist = Ngxconf.Domain_m[dom]
			Ngxconf.RUnlock()
			if domexist {
				dominfo.Blk_http = ""
				dominfo.Blk_str = ""
				domexist = false
				//lprintf(4, "[ERROR] exist domain in the map... something wrong.")
				//os.Exit(1)
			}

			dominfo.Intime = time.Now()
			dominfo.Status = "positive"
		}

		if strings.HasPrefix(line, "#domain end") {
			Ngxconf.Lock()
			Ngxconf.Domain_m[dom] = dominfo
			Ngxconf.Unlock()
			dom = ""
			domexist = true
		}

		if strings.Contains(line, "#port open") {

			setInitPortMap(portinfo)
			//portinfo = new(BlockInfo)
			//portinfo.close = make(chan bool)
			portinfo.ssl = false
			portinfo.crt = ""
			portinfo.key = ""
			portinfo.ln_flg = false
		}
	}

	if err := scanner.Err(); err != nil {
		lprintf(1, "[NGINX] nginx config file read error (%s)\n", err)

		//details := "nginx config file read error - " + err.Error()
		//agent_sendErr(ERR_NGX_CONF, "", "", "", details)

	}

	return
}

/*func load_conf(fname string) {
	// smartNginx page setting
	lprintf(4, "[INFO] nginx config load start (%s)\n", fname)

	file, err := os.Open(fname)
	if err != nil {
		lprintf(1, "[FAIL] can not open nginx config file (%s)", fname)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	mode := COMMON_BLOCK

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#http block") { // http block
			lprintf(4, "[INFO] config find http block(%s)\n", line)
			mode = HTTP_BLOCK
		} else if strings.HasPrefix(line, "#stream block") { // stream block
			lprintf(4, "[INFO] config find stream block(%s)\n", line)
			mode = STREAM_BLOCK
		}

		// make port map
		if strings.HasPrefix(line, "listen ") {
			port := strings.TrimSpace(line[7 : len(line)-1])
			iport := 0

			if strings.HasSuffix(port, "ssl") {
				iport, _ = strconv.Atoi(port[:len(port)-4])
				setInitPortMap(iport, true, mode)
			} else {
				iport, _ = strconv.Atoi(port)
				setInitPortMap(iport, false, mode)
			}

			lprintf(4, "[INFO] config find listen port (%s) -> (%d)\n", port, iport)
		}

		// make fqdn map
		if strings.HasPrefix(line, "server_name ") {
			sname := strings.TrimSpace(line[12 : len(line)-1])
			lprintf(4, "[INFO] config find server name insert map (%s)\n", sname)
			setInitFqdnMap(sname, "", true, mode)
		}
	}

	if err := scanner.Err(); err != nil {
		lprintf(1, "[FAIL] ningx config file read error (%s)\n", err)
	}

	return
}*/
/*func allconf() string {
	var all string

	all = ngxconf.Blk_common

	all += "http {\n"
	for key, val := range ngxconf.Domain_m {
		if val.Status == "negative" {
			continue
		}
		lprintf(4, "key(%s) write", key)
		all += val.Blk_http
	}
	all += "\n}\n"

	all += "stream {\n"
	for key, val := range ngxconf.Domain_m {
		if val.Status == "negative" {
			continue
		}
		all += val.Blk_str
	}
	all += "\n}\n"

	return all
}*/
/*func xml_converter(xml_str string) string {

	var conf_str string // 새로운 conf 내용

	//xml 구조체에 저장
	var conf types.Conf_s

	var tabcnt int

	xml.Unmarshal([]byte(xml_str), &conf)

	//conf구조체 for문으로 돌면서 내용물 conf 포맷쓰기(string으로)
	for i := 0; i < 1; i++ { //일단 conf block 1개 뿐이니까.

		if conf.Domain != "" {
			conf_str += "domain " + conf.Domain + ";\n"
		}
		if conf.User != "" {
			conf_str += "user " + conf.User + ";\n"
		}
		if conf.Worker_proc != "" {
			conf_str += "worker_processes " + conf.Worker_proc + ";\n"
		}
		if conf.Events.Worker_conn != "" {
			conf_str += "\nevents {\n worker_connections " + conf.Events.Worker_conn + ";\n}\n"
		}

		for index_errl := 0; index_errl < len(conf.Error_log); index_errl++ {
			conf_str += "error_log " + conf.Error_log[index_errl] + ";\n"
		}

		for index_http := 0; index_http < len(conf.Http); index_http++ {
			http := conf.Http[index_http]

			conf_str += "\nhttp {\n"

			tabcnt++

			if http.Include != "" {
				conf_str += write_tab(tabcnt) + "include " + http.Include + ";\n"
			}

			conf_str += write_inside(http.Server, http.Upstream, tabcnt)

			tabcnt--
			conf_str += write_tab(tabcnt) + "}\n"
		}

		for index_stream := 0; index_stream < len(conf.Stream); index_stream++ {
			stream := conf.Stream[index_stream]

			conf_str += "\nstream {\n"

			tabcnt++

			conf_str += write_inside(stream.Server, stream.Upstream, tabcnt)

			tabcnt--
			conf_str += write_tab(tabcnt) + "}\n"
		}
	}
	for index_srv := 0; index_srv < len(http.Server); index_srv++ {
				server := http.Server[index_srv]

				conf_str += write_tab(tabcnt) + "server {\n"

				tabcnt++

				if server.Listen != "" {
					conf_str += write_tab(tabcnt) + "listen " + server.Listen + ";\n"
				}
				if server.Server_name != "" {
					conf_str += write_tab(tabcnt) + "server_name " + server.Server_name + ";\n"
				}
				if server.Ssl_certi != "" {
					conf_str += write_tab(tabcnt) + "ssl_certificate " + server.Ssl_certi + ";\n"
				}
				if server.Ssl_sess_cache != "" {
					conf_str += write_tab(tabcnt) + "ssl_session_cache " + server.Ssl_sess_cache + ";\n"
				}
				if server.Ssl_certi_key != "" {
					conf_str += write_tab(tabcnt) + "ssl_certificate_key " + server.Ssl_certi_key + ";\n"
				}
				if server.Ssl_sess_timeout != "" {
					conf_str += write_tab(tabcnt) + "ssl_session_timeout " + server.Ssl_sess_timeout + ";\n"
				}
				if server.Ssl_ciphers != "" {
					conf_str += write_tab(tabcnt) + "ssl_ciphers " + server.Ssl_ciphers + ";\n"
				}

				for index_loc := 0; index_loc < len(server.Location); index_loc++ {
					loca := server.Location[index_loc]

					conf_str += "\n" + write_tab(tabcnt) + "location "
					if loca.Name != "" {
						conf_str += loca.Name + " { \n"
					}

					tabcnt++

					if loca.Index != "" {
						conf_str += write_tab(tabcnt) + "index " + loca.Index + ";\n"
					}

					for index_pp := 0; index_pp < len(loca.Proxy_pass); index_pp++ {
						conf_str += write_tab(tabcnt) + "proxy_pass " + loca.Proxy_pass[index_pp] + ";\n"
					}

					if loca.Root != "" {
						conf_str += write_tab(tabcnt) + "root " + loca.Root + ";\n"
					}
					tabcnt--
					conf_str += write_tab(tabcnt) + "}\n"

				}
				tabcnt--
				conf_str += write_tab(tabcnt) + "}\n"

			}
			//lprintf(4, "confstr2:(%s)\n", conf_str)
			for index_upst := 0; index_upst < len(http.Upstream); index_upst++ {
				upstream := http.Upstream[index_upst]

				conf_str += "\n" + write_tab(tabcnt) + "upstream {\n"

				tabcnt++

				if upstream.Keepalive != "" {
					conf_str += write_tab(tabcnt) + "keepalive " + upstream.Keepalive + ";\n"
				}
				if upstream.Name != "" {
					conf_str += write_tab(tabcnt) + "name " + upstream.Name + ";\n"
				}
				if upstream.Server != "" {
					conf_str += write_tab(tabcnt) + "server " + upstream.Server + ";\n"
				}
				tabcnt--
				conf_str += write_tab(tabcnt) + "}\n"
			}
			tabcnt--
			conf_str += write_tab(tabcnt) + "}\n"

		}

	}

	//lprintf(4, "last confstr:(%s)\n", conf_str)
	return conf_str
}*/
