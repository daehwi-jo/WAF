package smartidle

type Main_xml struct {
	Conf []Conf_s `xml:"conf"`
}

type Conf_s struct {
	User        string   `xml:"user"`
	Worker_proc string   `xml:"worker_processes"`
	Error_log   []string `xml:"error_log"`

	Domain string `xml:"domain"`
	Status string `xml:"status"`

	Cache []Cache_s `xml:"cacheinfo"`

	Http    Http_s      `xml:"http"`
	Stream  Stream_s    `xml:"stream"`
	Ipsinfo []Ipsinfo_s `xml:"ipsinfo"`
	//WebFilter []WebFilter_s `xml:"webfilter"`

	Dom_ver string `xml:"domainversion"`
	Ips_ver string `xml:"ipsversion"`
	//WebFilter_ver string `xml:"webfilterversion"`

	Events Event_s `xml:"events"`
}

type Cache_s struct {
	Host      string `xml:"host"`      // host 이름
	CacheSize string `xml:"cachesize"` // 한 파일의 cache 양 (파일 많)
	Inactive  string `xml:"inactive"`  // host별 캐쉬 유지 시간
	KeyMemory string `xml:"keymemory"` // host별 사용하는 전체 cache 양
}

/*
type WebFilter_s struct {
	Server_name string `xml:"server_name"` // fqdn (hostname)
	Server_id   int    `xml:"server_id"`   // hostid, host에 해당하는 web filter 정보

	Header string `xml:"header"` // header
	//Type      string `xml:"type"`      // type(char, int)
	//Condition string `xml:"condition"` // condition(like, not like)
	Value string `xml:"value"` // header value
	//Action    string `xml:"action"`    // accept -> A, drop -> D
	Case int `xml:"case"` // case 1-like, 2-not like, 3-greater than, 4-less than

	DefUse     int `xml:"defUse"`     // defence use -> 1 : 차단, 0 : 보고
	CaptchaUse int `xml:"captchaUse"` // captcha use -> 1 : 사용, 0 : 미 사용
}
*/

type WebFilter_s struct {
	Header string `xml:"header"` // header key
	Value  string `xml:"value"`  // header value
	Case   int    `xml:"case"`   // 1,2,3,4
	/*
	   1 -> 포함 패스 / 미 포함 드랍
	   2 -> 포함 드랍 / 미 포함 패스
	   3 -> 크다 드랍 / 작다 패스
	   4 -> 크다 패스 / 작다 드랍
	*/
}

type Ipsinfo_s struct {
	Server_name string `xml:"server_name"` // fqdn (hostname)
	Server_id   int    `xml:"server_id"`   // hostid, host에 해당하는 ips 정보

	HttpCnt     int    `xml:"HttpCnt"`     // http 패킷의 count 감지
	HttpPeriod  int    `xml:"HttpPeriod"`  // http 패킷의 요청 최대 횟수 허용 시간
	HttpExcept  string `xml:"HttpExcept"`  // http header의 uri를 비교하여 요청 횟수 count에서 제외
	HttpCmd     string `xml:"HttpCmd"`     // http header의 cmd 검사
	HttpMaxSize int    `xml:"HttpMaxSize"` // http 패킷의 길이와 max size 비교하여 대응
	HttpFilter  string `xml:"HttpFilter"`  // http 패킷에 해당 데이터가 없을경우 대응

	DefUse         int `xml:"defUse"`         // defence use -> 1 : 차단, 0 : 보고
	CaptchaUse     int `xml:"captchaUse"`     // idle client captcha use -> 1 : 사용, 0 : 미 사용
	NginxCaptchaYN int `xml:"nginxCaptchaYn"` // nginx fqdn captcha use -> 1 : 사용, 0 : 미 사용

	PlusonType     string `xml:"plusonType"` // matrix, group, rcs
	PlusonDestIp   string `xml:"destIp"`
	PlusonDestPort string `xml:"destPort"`

	WebFilter []WebFilter_s `xml:"webfilter"` // http webfilter
}

type Stream_s struct {
	Server   []Server_s   `xml:"server"`
	Upstream []Upstream_s `xml:"upstream"`
}

type Http_s struct {
	Server   []Server_s   `xml:"server"`
	Upstream []Upstream_s `xml:"upstream"`
	//Server_name string      `xml:"server_name"` // fqdn
	//Server_id   int         `xml:"server_id"`   // hostid
	//WebFilter   WebFilter_s `xml:"webfilter"`
	//Ipsinfo     Ipsinfo_s   `xml:"ipsinfo"`

	/*
		Include              string   `xml:"include"`
		Defalt_type          string   `xml:"default_type"`
		Proxy_header         []string `xml:"proxy_set_header"`
		Sendfile             string   `xml:"sendfile"`
		Keepal_timeout       string   `xml:"keepalive_timeout"`
		Proxy_http_version   string   `xml:"proxy_http_version"`
		Proxy_cache_valid    []string `xml:"proxy_cache_valid"`
		Limit_req_log_level  string   `xml:"limit_req_log_level"`
		Limit_conn_log_level string   `xml:"limit_conn_log_level"`
		Limit_conn_zone      string   `xml:"limit_conn_zone"`
		Limit_req_zone       string   `xml:"limit_req_zone"`
	*/
}

type Server_s struct {
	Listen      []string `xml:"listen"`
	Server_name string   `xml:"server_name"`

	Proxy_pass string `xml:"proxy_pass"`
	//Sql_inject string `xml:"sql_inject"`
	Resolver string `xml:"resolver"`

	Ssl_certi        string `xml:"ssl_certificate"`
	Ssl_certi_key    string `xml:"ssl_certificate_key"`
	Ssl_sess_cache   string `xml:"ssl_session_cache"`
	Ssl_sess_timeout string `xml:"ssl_session_timeout"`
	Ssl_ciphers      string `xml:"ssl_ciphers"`

	Location []Location_s `xml:"location"`

	Cache     string `xml:"cache"`
	Injection string `xml:"injection"`
	Filectl   string `xml:"filectl"`
	Captcha   string `xml:"captcha"`
	Autocache string `xml:"autocache"`
}

type Event_s struct {
	Worker_conn string `xml:"worker_connections"`
}

type Location_s struct {
	Name       string   `xml:"name"`
	Root       string   `xml:"root"`
	Proxy_pass []string `xml:"proxy_pass"`
	Index      string   `xml:"index"`

	Conditional []Conditional_s `xml:"conditional"`
}

type Upstream_s struct {
	Name      string `xml:"name"`
	Server    string `xml:"server"`
	Keepalive string `xml:"keepalive"`
}

type Conditional_s struct {
	State      string `xml:"state"`
	Proxy_pass string `xml:"proxy_pass"`
}
