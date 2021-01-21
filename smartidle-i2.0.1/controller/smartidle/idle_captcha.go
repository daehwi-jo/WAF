package smartidle

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"charlie/i0.0.2/cls"
	"github.com/dchest/captcha"
	"github.com/julienschmidt/httprouter"
	types "smartidle/smartidle-i2.0.1/model/smartidle"
)

// detekt client의 접속 정보를 통해 service fqdn을 확인
func Response_cInfo(h http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	rd, err := ioutil.ReadAll(r.Body)
	if err != nil {
		cls.Renderer.Text(h, http.StatusOK, "NULL")
		return
	}

	ClientInfo.RLock()
	fqdn, exists := ClientInfo.m[string(rd)]
	ClientInfo.RUnlock()

	if !exists {
		lprintf(4, "[INFO] client(%s) fqdn null \n", string(rd))
		cls.Renderer.Text(h, http.StatusOK, "NULL")
		return
	}

	lprintf(4, "[INFO] client(%s) fqdn(%s) \n", string(rd), fqdn)
	cls.Renderer.Text(h, http.StatusOK, fqdn)
}

//runtime.NumGoroutine() //돌고있는 goroutine 갯수 확인
func Response_first(h http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	//	lprintf(4, "[[[[[[[[[[[[[[[first request(%s)]]]]]]]]]]]]]]]]\n", r.RequestURI)

	lprintf(4, "[INFO] CAPTCHA - Host (%s) ", r.Host)
	/*	//FqdnMap
		FqdnMap.RLock()
		fqdninfo, exist := FqdnMap.m[fqdn]
		FqdnMap.RUnlock()

		if !exist {
			lprintf(1, "[ERROR] CAPTCHA - Not Serviced Host (%s)", fqdn)
			return
		}

		fqdninfo.IpsInfo.
	*/

	var tmpl = types.Templ{}

	get_seq := r.FormValue("img_seq")
	seq, _ := strconv.Atoi(get_seq)

	if get_seq == "" { // 새로운 client 추가
		//lprintf(4, "[[[[[[[[[[[[[[[first request]]]]]]]]]]]]]]]]\n")

		tmpl.Seq = make_seq()
		//lprintf(4, "make_seq done - seq(%d)\n", tmpl.Seq)

	} else { //있던애가 또들어온 경우는 refresh
		//lprintf(4, "[[[[[[[[[[[[[[[refresh request- seq(%d)]]]]]]]]]]]]]]]]\n", seq)

		tmpl.Seq = seq

	}
	lprintf(4, "[INFO] captcha seq(%d)\n", tmpl.Seq)

	cls.Renderer.HTML(h, http.StatusOK, "smartidle/captcha", tmpl)

}
func response_incorrect(h http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	//lprintf(4, "[[[[[[[[[[[[[[[incorrect request]]]]]]]]]]]]]]]]\n")

	get_seq := r.FormValue("img_seq")

	if get_seq == "" {
		lprintf(4, "[INFO] CAPTCHA - no seq num\n")
		Response_first(h, r, ps)
		return
	}
	var tmpl = types.Templ{}
	seq, _ := strconv.Atoi(get_seq)
	tmpl.Seq = seq

	cls.Renderer.HTML(h, http.StatusOK, "smartidle/captcha_incorrect", tmpl)

}
func response_timeout(h http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	//lprintf(4, "[[[[[[[[[[[[[[[timeout request]]]]]]]]]]]]]]]]\n")

	get_seq := r.FormValue("img_seq")

	if get_seq == "" {
		lprintf(4, "[INFO] CAPTCHA - no seq num\n")
		Response_first(h, r, ps)
		return
	}

	var tmpl = types.Templ{}
	tmpl.Seq = make_seq()

	//lprintf(4, "[timeout]make_seq done - seq(%d)\n", tmpl.Seq)

	cls.Renderer.HTML(h, http.StatusOK, "smartidle/captcha", tmpl)
	//	cls.Renderer.HTML(h, http.StatusOK, "smartidle/captcha_timeout", tmpl)

}

func Response_image(h http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	lprintf(4, "[INFO] response_image call")

	client_img := ps.ByName("client_img")
	client_num := strings.TrimRight(client_img, ".gif")
	if client_num == "" || client_num == "favicon.ico" {
		lprintf(1, "[WARN] CAPTCHA - Seq num was not downloaded with the tmpl(%s)\n", client_num)

		Response_first(h, r, ps)
		return
	}
	//	lprintf(4, "client_num:(%s)\n", client_num)
	seq, _ := strconv.Atoi(client_num)

	h.Header().Set("Content-Type", "image/gif")

	img_bytes, digits := Make_capimg(Idle_t.Imgpath)
	lprintf(4, "[INFO] captcha make data(%s) \n", digits)

	//map에 저장
	captcha_m[seq] = types.ClientInfo{seq, digits, time.Now()}

	//timer 동작 시작
	go captcha_timer(captcha_m[seq].Oldtime, seq)

	cls.Renderer.Data(h, http.StatusOK, img_bytes)

}

func response_final(h http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	ttime := fmt.Sprintf("%.12d", time.Now().Unix())
	cookie := http.Cookie{Name: "gotcha", Value: ttime + GetMD5Hash(ttime+"INNOSALT")}
	http.SetCookie(h, &cookie)

	h.Header().Set("Content-Type", "application/x-www-form-urlencoded")

	lprintf(4, "[INFO] referer(%s), host(%s)", r.Referer(), r.Host)

	var referer string
	if strings.HasSuffix(r.Referer(), "/ans_captcha") {
		referer = strings.TrimRight(r.Referer(), "/ans_captcha")
	} else if strings.HasSuffix(r.Referer(), "/req") {
		referer = strings.TrimRight(referer, "/req")
	} else {
		referer = r.Referer()
	}

	//referer = "https://vueui.securitynetsvc.com:15001/"

	/*
		lprintf(4, "[INFO] Final referer:(%s)\n", referer)

		h.Header().Set("Location", referer)
	*/

	/*
		var referer string

		fqdns := strings.Split(r.Referer(), ":")
		if len(fqdns) > 1 {
			referer = fqdns[0] + ":" + fqdns[1]
		} else {
			referer = r.Referer()
		}
	*/
	//referer := r.Referer()

	cInfos := strings.Split(r.RemoteAddr, ":")
	C.RWMutex.Lock()
	cInfo, exists := C.m[cInfos[0]]
	if exists {
		cInfo.cCnt = 0
		cInfo.sTime = int(time.Now().Unix())
		referer = cInfo.url
		C.m[cInfos[0]] = cInfo
	}
	C.RWMutex.Unlock()

	h.Header().Set("Location", referer)
	lprintf(4, "[INFO] location (%s) \n", referer)

	//lprintf(4, "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@(/n%s)", h.)
	cls.Renderer.Text(h, 301, "captcha finish")
}

func Check_form(h http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	//http.StatusOK
	//	lprintf(4, "[[[[[[[[[[[[[[[check form]]]]]]]]]]]]]]]]\n")
	//seq number에 맞는 client se	qnum 가져오기

	lprintf(4, "[INFO] check form call \n")

	get_seq := r.FormValue("img_seq")
	if get_seq == "" {
		lprintf(1, "[WARN] CAPTCHA - The client has no sequence number.\n ")
		cls.Renderer.Text(h, http.StatusInternalServerError, "no sequence number")
		//req_timeout(h, r, ps)
		return
	}
	seq, _ := strconv.Atoi(get_seq)

	//refresh는 무조건 refresh
	isrefresh := r.FormValue("refresh")
	if isrefresh == "1" {
		timer_off_seq <- seq

		Response_first(h, r, ps)
		return
	}

	//timeout 확인
	_, exist := captcha_m[seq]
	if exist == false { //timeout 되면 map에서 delete 되니까 없음
		lprintf(4, "[INFO] CAPTCHA - deleted client info\n")
		response_timeout(h, r, ps)
		return
	}

	//refresh도 아니고 timeout도 아닌 경우 숫자 비교
	get_digits := r.FormValue("captchaInput")

	lprintf(4, "[INFO] CAPTCHA - info: %s, %s \n", get_digits, captcha_m[seq].Digits)

	if get_digits == captcha_m[seq].Digits {

		// 인증이 통과 되면 해당 timer off, client data 삭제
		timer_off_seq <- seq
		delete(captcha_m, seq)

		response_final(h, r, ps)

		return

	} else {
		//	lprintf(4, "incorrect: %s, %s\n", get_digits, captcha_m[seq].Digits)
		//틀린경우 - timer off
		timer_off_seq <- seq

		response_incorrect(h, r, ps)
		return
	}
}

//img 만들기
func Make_capimg(dest string) ([]byte, string) {

	if dest == "" {
		lprintf(1, "[FAIL] CAPTCHA - Image file name does not exist")

		//details := "image file name wrong "
		//agent_sendErr(ERR_FILE_CAPIMG, "", "", "", details)

		return []byte(""), ""
	}

	f, err := os.Create(dest)
	if err != nil {
		lprintf(1, "[ERROR] CAPTCHA - creating file failed")

		//details := "creating image file failed"
		//agent_sendErr(ERR_FILE_CAPIMG, "", "", "", details)

		return []byte(""), ""
	}

	defer f.Close()

	//setting the values
	digit_len := 6
	img_width := 240
	img_height := 80

	//making the image

	var w io.WriterTo

	var str_digits string

	digits := captcha.RandomDigits(digit_len) //[]byte return

	for i := 0; i < len(digits); i++ {
		str_digits = str_digits + strconv.Itoa(int(digits[i]))
	}

	//	lprintf(4, "/////%s\n", str_digits)

	w = captcha.NewImage("", digits, img_width, img_height)

	_, err = w.WriteTo(f)
	if err != nil {
		lprintf(1, "[FAIL] CAPTCHA - writing to image file")

		//details := "writing to image file failed"
		//agent_sendErr(ERR_FILE_CAPIMG, "", "", "", details)

		return []byte(""), ""
	}

	img_bytes := img_to_bytes(dest)

	return img_bytes, str_digits
}

func img_to_bytes(img_path string) []byte {

	file, err := os.Open(img_path)

	if err != nil {
		lprintf(1, "[FAIL] CAPTCHA - %s", err.Error())

		//details := "image file open failed"
		//agent_sendErr(ERR_FILE_CAPIMG, "", "", "", details)

		return []byte("")
	}

	defer file.Close()

	fileInfo, _ := file.Stat()
	var size int64 = fileInfo.Size()
	bytes := make([]byte, size)

	// read file into bytes
	buffer := bufio.NewReader(file)
	_, err = buffer.Read(bytes)

	//lprintf(4, "image bytes: %s\n", bytes)

	return bytes
}

func make_seq() int {

	if len(captcha_m) == 0 {

		return 0
	}

	index := 0

	var key int

	for key = range captcha_m {
		if key <= index {
			break
		}
		_, exist := captcha_m[index]
		if exist == false { // 빈공간이 있으면 해당 index return
			return index
		}
		index++
	}

	return key + 1 //다 차있을 경우 새 공간 할당

}
