package smartidle

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"charlie/i0.0.2/cls"
	"github.com/julienschmidt/httprouter"
)

// client 캡차여부 체크
var C = struct {
	sync.RWMutex
	m map[string]cInfo //(client ip, connect cnt)
	//f map[string]string // (fqdn, dest 정보)

	Btime int // block time 10초 동안
	Bcnt  int // block cnt 10번 오면 -> captcha 발송
}{m: make(map[string]cInfo)}

type cInfo struct {
	sTime int    // start time
	cCnt  int    // connect cnt
	url   string // connect url
}

func check_captcha(ip string, port int, connectUrl string) bool {

	C.RWMutex.Lock()
	cInfo, exists := C.m[ip]
	defer C.RWMutex.Unlock()

	nTime := int(time.Now().Unix())

	if !exists {
		lprintf(4, "[INFO] new connect client(%s) captcha make \n", ip)

		cInfo.cCnt = 1
		cInfo.sTime = nTime
		cInfo.url = connectUrl
		C.m[ip] = cInfo
		return false
	}

	if nTime-cInfo.sTime < C.Btime && cInfo.cCnt >= C.Bcnt {
		lprintf(4, "[INFO] bad connect client(%s) captcha go \n", ip)
		return true
	} else if nTime-cInfo.sTime > C.Btime {
		lprintf(4, "[INFO] old connect client(%s) captcha delete \n", ip)

		delete(C.m, ip)
		return false
	}

	cInfo.cCnt += 1
	lprintf(4, "[INFO] connect client(%s) captcha cnt(%d) \n", ip, cInfo.cCnt)
	cInfo.url = connectUrl
	C.m[ip] = cInfo

	return false
}

func compare_domain(fqdn, domain string) bool {

	flag := true

	tmp1 := strings.Split(domain, ".")
	len1 := len(tmp1)

	tmp2 := strings.Split(fqdn, ".")
	len2 := len(tmp2)

	if len1 > len2 {
		return false
	}

	for i := 1; i <= len1; i++ {
		//lprintf(4, "[INFO] compare string(%s), (%s) \n", tmp1[len1-i], tmp2[len2-i])
		if tmp1[len1-i] != tmp2[len2-i] {
			flag = false
			break
		}
	}

	//lprintf(4, "[INFO] check domain, fqdn(%s) - domain(%s), result : %t \n", fqdn, domain, flag)

	return flag

}

//lprintf(4,"aaaaaaa)
func sphere_timer(time_intv int) {
	lprintf(4, "[INFO] new sphere_timer start ::: Time interval(%d)\n", time_intv)

	start := time.Now()
	ticker := time.NewTicker(1 * time.Second)

	for now := range ticker.C {

		d := int(now.Sub(start).Seconds())
		//lprintf(4, "diff:%d\n", d)
		if d > time_intv {
			lprintf(4, "[INFO] (%d)sec time out , Time to check the Sphere.\n", time_intv)

			//sphere 에서  받아와서 처리
			//gset_sphere_data()

			go sphere_timer(time_intv) // 새로운 타이머 작동하고
			return                     // 만료된 타이머 종료
		}
	}
}

func captcha_timer(oldtime time.Time, seq int) {
	lprintf(4, "[INFO] CAPTCHA - timer start\n")
	ticker := time.NewTicker(1 * time.Second)
	//time.After(5 * time.Second)
	for now := range ticker.C {
		select {
		case off_seq := <-timer_off_seq:
			if off_seq == seq {
				lprintf(4, "[INFO] CAPTCHA - client seq(%d) send a message, stop the timer\n", seq)
				timer_off_seq <- -1
				return
			}
		default:
			d := int(now.Sub(oldtime).Seconds())
			//lprintf(4, "diff:%d\n", d)
			if d > 180 {
				lprintf(4, "[INFO] CAPTCHA - client seq(%d) time out - delete client(%d)\n", seq, seq)
				delete(captcha_m, seq)
				return
			}
		}

		//lprintf(4, "timer2222...\n")
	}

	//	ticker.Stop()
	//time.Sleep(5 * time.Second)
}

func GetMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func copy_file(src, dst string) error {
	srcfile, _ := os.OpenFile(src, os.O_CREATE|os.O_RDWR, os.FileMode(0644))

	defer srcfile.Close()

	dstfile, _ := os.Create(dst)

	defer dstfile.Close()

	_, err := io.Copy(dstfile, srcfile)
	if err != nil {
		return err
	}

	//lprintf(4, "[INFO] copy file success : from(%s) -> to(%s)", src, dst)

	return nil
}

/*
func getHeaderValue(packet []byte, header string) (string, int) {

	var value string

	headers := strings.Split(string(packet), "\r\n")
	for i := 0; i < len(headers); i++ {
		row := headers[i]
		if strings.HasPrefix(row, header) {
			row_arr := strings.Split(row, ":")

			if len(row_arr) == 2 {
				value = strings.TrimSpace(row_arr[1])
			}

			return value, 0

		}
	}

	return "", -1
}
*/

func getHeaderValue(packet []byte, header string) (string, int, int) {

	lprintf(4, "[INFO] getHeaderValue(%s) \n", header)

	idx := bytes.Index(packet, []byte(header))

	if idx == -1 {
		lprintf(4, "[INFO] getHeaderValue return -1 \n")
		idx = 0
	}

	headers := strings.Split(string(packet[idx:]), "\r\n")
	for i := 0; i < len(headers); i++ {
		row := headers[i]
		if strings.HasPrefix(row, header) {
			row_arr := strings.Split(row, ":")

			if len(row_arr) == 2 || len(row_arr) == 3 {
				return strings.TrimSpace(row_arr[1]), 0, idx
			} else {
				return "", -1, idx
			}
		}
	}

	return "", -1, idx
}

func delHeaderValue(packet []byte, header string) (int, []byte, int) {

	//lprintf(4, "[INFO] del header(%s) \n", header)
	//lprintf(4, "[INFO] old packet(%s) \n", string(packet))

	idx := bytes.Index(packet, []byte(header))

	if idx == -1 {
		return -1, packet, 0
	}

	headers := strings.Split(string(packet[idx:]), "\r\n")
	rmLen := len(headers[0])
	copy(packet[idx:], packet[idx+rmLen+2:])
	packet = packet[:len(packet)-(rmLen+2)]

	//lprintf(4, "[INFO] new packet(%s) \n", string(packet))

	return 1, packet, rmLen + 2
}

// packet, read len, http header key, http header value
func inHeaderValue(packet []byte, hlen int, headerKey, headerValue string) ([]byte, int) {

	header := headerKey + ": " + headerValue
	b := make([]byte, hlen+len(header)+2)
	forString := []byte(header)
	flen := len(header)
	//hlen := bytes.Index(packet, []byte(header)) + 4

	//lprintf(4, "[INFO] in packet : %s\n", string(packet[:hlen]))
	//lprintf(4, "[INFO] in hlen : %d\n", hlen)

	copy(b, packet[:hlen-2])
	copy(b[hlen-2:], forString[:flen])
	copy(b[len(b)-4:], []byte("\r\n\r\n"))

	return b, len(header) + 2
}

func addHeaderValue(packet []byte, hlen int, title, value string) []byte {
	//	lprintf(4, "hlen(%d)", hlen)

	header := packet[:hlen+2]

	new_packet := string(header) + title + ": " + value
	new_packet += string(packet[hlen:])

	return []byte(new_packet)
}

func get_hlength(packet []byte) int {
	//var hlen int

	hb := strings.Split(string(packet), "\r\n\r\n") //header+body
	if len(hb) == 0 {
		lprintf(1, "[FAIL] can not receive whole http header (%s)\n", packet)
		return -1
	}

	return len(hb[0])
}

func req_client_url(buf string) int { //udp cache에서 사용하는 함수
	if strings.Contains(buf, "favicon.ico") == true {
		return 0
	}

	datas := strings.Split(buf, ";")

	var url string

	for i, data := range datas {
		if i == 0 {
			url = "http://"
		} else {
			url += data
		}
	}

	//url = "http://www.google.com":
	resp, err := http.Get(url)
	if err != nil {
		lprintf(1, "[FAIL] UDP CACHE - Request Client's URL http.Get fail (%s)", err.Error())
		return -1
	}
	defer resp.Body.Close()

	f, err := os.Open("/dev/null")
	defer f.Close()

	resp.Write(f)

	lprintf(4, "[INFO] UDP CACHE - Request Client's URL(%s) success. (to /dev/null)", url)

	return 0

	/*exe := exec.Command("curl", "-l", "-o", "/dev/null", client_url)
	exe := exec.Command("curl www.google.com")
	if err := exe.Run(); err != nil {
		lprintf(4, "[FAIL] Request Client URL run command fail (%s)", err.Error())
		return -1
	}*/

}

func cache_clear(h http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	lprintf(4, "[INFO] cache cleaer call \n")

	if Idle_t.CACHE_DIR == "" {
		lprintf(4, "[INFO] Cache Directory is NULL\n")
		return
	}

	files, err := ioutil.ReadDir(Idle_t.CACHE_DIR)
	if err == nil {
		for _, k := range files {
			rpath := fmt.Sprintf("%s/%s", Idle_t.CACHE_DIR, k.Name())
			lprintf(4, "%s remove\n", rpath)
			os.RemoveAll(rpath)

		}
	}
	//h.Header().Set("Server", "smartidle")

	msg1 := "Standard response for successful HTTP requests."
	msg2 := "The actual response will depend on the request method used."
	msg3 := " In a GET request, the response will contain an entity corresponding to the requested resource."
	msg4 := "In a POST request the response will contain an entity describing or containing the result of the action."

	cls.Renderer.Text(h, http.StatusOK, msg1+msg2+msg3+msg4)

}

func getpubip() string {
	//for test : httpFqdn :="http://192.168.18.58/ip"
	//real : httpFqdn := "http://what-is-myip.net"
	httpFqdn := "http://192.168.18.58/ip"

	resp, err := http.Get(httpFqdn)
	if err != nil {
		lprintf(1, "[ERROR] http get err(%s) \n", err.Error())
		return ""
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		lprintf(1, "[ERROR] response body read err(%s) \n", err.Error())
		return ""
	}
	defer resp.Body.Close()

	// body parsing
	htmlParse := strings.Split(string(data), "<body>")
	htmlParse = strings.Split(htmlParse[1], "</body>")

	return strings.TrimSpace(htmlParse[0])
}

func FileExist(fname string) bool {
	//lprintf(4,"file check!")
	if _, err := os.Stat(fname); os.IsNotExist(err) {
		//	lprintf(4,"file nnnnnnnnnnnnnnn")
		return false
	}

	// 존재
	return true
}

func print_ips() {
	lprintf(4, "----------------PRINT IPS--------------------")
	for key, val := range FqdnMap.m {
		ips := val.IpsInfo
		lprintf(4, "[INFO] IPSRULE(%s) id(%d), cnt(%d), period(%d), except(%s), cmdlist(%s), maxsize(%d), filter(%s), captchaUse(%d), defUse(%d)", key, ips.id, ips.cnt, ips.period, ips.except, ips.cmdList, ips.maxsize, ips.filter, ips.captchaUse, ips.defUse)

		for _, wf := range ips.Wf {
			lprintf(4, "[INFO] HTTP WEB FILTER key(%s) value(%s) case(%d) \n", wf.key, wf.value, wf.wCase)
		}

	}
	lprintf(4, "----------------PRINT IPS DONE--------------------")
}

/*
func print_wf() {
	lprintf(4, "----------------PRINT WEBFILTER--------------------")
	for key, val := range FqdnMap.m {
		lprintf(4, "WFRULE(%s)", key)
		for server, wf := range val.Wf {
			lprintf(1, "server name(%s), key(%s), value(%s), case(%d), captchaUse(%d), defUse(%d)", server, wf.key, wf.value, wf.wCase, wf.captchaUse, wf.defUse)
		}
	}
	lprintf(4, "----------------PRINT WEBFILTER DONE--------------------")
}
*/

func print_conf() {
	lprintf(4, "----------------print map start--------------------")
	for key, _ := range Ngxconf.Domain_m {

		lprintf(4, "domain circular(%s)", key)

	}
	lprintf(4, "----------------print map done--------------------")
}

/*
func myip(port string) {
	lprintf(4, "[INFO] MyIP PORT (%s) OPEN, Listening start", port)

	mux := http.NewServeMux()

	mux.HandleFunc("/", handle_myip)
	http.ListenAndServe(":"+port, mux)
}
*/

func handle_myip(w http.ResponseWriter, r *http.Request) {
	hosts := "*.ipip.kr what-is-myip.net what-is-myip.org ip-servers.net ip-servers.org edge-ipconfig.com edge-ipconfig.net edge-findip.com edge-findip.net"

	lprintf(4, "[INFO] MyIP Host is (%s)", r.Host)
	if strings.Contains(hosts, r.Host) {
		w.Write([]byte(r.RemoteAddr))
		return
	}

	w.WriteHeader(http.StatusNotFound)
}

func GetCaptcha() string {

	time.Sleep(10 * time.Second)

	httpFqdn := "http://127.127.0.1:18900/req_captcha"

	lprintf(4, "[INFO] 1111111111111111111 \n")

	resp, err := http.Get(httpFqdn)
	if err != nil {
		lprintf(1, "[ERROR] http get err(%s) \n", err.Error())
		return ""
	}

	lprintf(4, "[INFO] 222222222222222222222 \n")

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		lprintf(1, "[ERROR] response body read err(%s) \n", err.Error())
		return ""
	}
	defer resp.Body.Close()

	lprintf(4, "[INFP] get captcha (%s) \n", string(data))

	return strings.TrimSpace(string(data))
}
