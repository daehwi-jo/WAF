package main

import (
	"fmt"
	"os"

	svc "smartidle/smartidle-i2.0.1/controller/smartidle"

	"charlie/i0.0.2/cls"
)

// function prototycommpe
var lprintf func(int, string, ...interface{}) = cls.Lprintf

//app_main(ad *cls.AppdataInfo)
func sub_main() {

	// http 요청 및 응답을 위한 URI 등록
	//logins := []cls.AppPages{
	//	{cls.LOGIN, "/login", nil, nil},
	//	{cls.LOGOUT, "/logout", nil, nil}, // 로그아웃 클릭시 호출
	//	// url can be accessed unless login
	//	{cls.EXCEPT, "/login,/login_auth,/public/css,/public/dist,/public/images,/public/js,/public/fonts,/favicon.ico,/", nil, nil},
	//}

	runPath := os.Args
	confDir := confDirString(runPath)
	checkfname := fmt.Sprintf("%s/conf/smartidle.ini", confDir)

	if _, err := os.Stat(checkfname); os.IsNotExist(err) {
		// config 경로에 smartidle.ini가 없을 경우 smartidleDns.ini 파일을 읽는다 (dns 장비에 80 proxy용)
		runPath[0] += "dns"
	}

	// config setting - return conf file nameHttpSendBody
	fname := cls.Cls_conf(runPath)
	lprintf(4, "[INFO] fname(%s) \n", fname)
	// config and page setting for application

	if svc.App_conf(fname) < 0 {
		lprintf(1, "[FAIL] not serviced nginx \n")
		return
	}

	//udp listen  port open
	/*v, r := cls.GetTokenValue("UDP_PORT", fname)
	if r != cls.CONF_ERR {
		go svc.Set_listen_udp(v)
		//	lprintf(4, "[FAIL] Udp listening failed\n")
		//	return
		//}
	}*/

	//svc.C.Btime = 10
	//svc.C.Bcnt = 10

	pages := []cls.AppPages{
		{cls.GET, "/", svc.Response_first, nil},
		{cls.GET, "/req_captcha", svc.Response_first, nil}, //request_html
		{cls.GET, "/req_captcha/", svc.Response_first, nil},
		{cls.GET, "/req_captcha/:client_img", svc.Response_image, nil}, //request_image
		{cls.POST, "/ans_captcha", svc.Check_form, nil},                //upload_form
		{cls.GET, "/clientInfo", svc.Response_cInfo, nil},              //client info -> get service fqdn
	}
	//go cls.Http_start(pages, nil)
	go cls.Http_startWithStateIP(pages, nil, cls.ListenIP, svc.FunConHandler)

	lprintf(4, "[INFO] set App_page \n")
	appPages := svc.App_page()
	if appPages == nil {
		lprintf(1, "[FAIL] not serviced application \n")
		return
	}

	lprintf(4, "[INFO] tp server started \n") // udp 12701 port
	go cls.Cls_start_idle(cls.App_data(svc.App_main), "127.127.0.1")

	lprintf(4, "[INFO] http server started \n") // tcp captcha 18900 port
	//cls.Http_startWithState(appPages, nil, svc.FunConHandler)
	cls.Http_startWithStateIP(appPages, nil, "127.127.0.1", svc.FunConHandler)

}

func confDirString(args []string) string {
	var length int = len(args)
	var dir string

	for i := 2; i < length; i++ {
		// log 옵션이나 background mark 이면 추가 하지 않음
		if args[i] == "-L" || args[i] == "&" {
			break
		}

		if i == 2 {
			dir = fmt.Sprintf("%s", args[i])
		} else if i > 2 && args[i] != "-e" {
			dir += fmt.Sprintf(" %s", args[i])
		} else {
			break
		}
	}

	return dir
}
