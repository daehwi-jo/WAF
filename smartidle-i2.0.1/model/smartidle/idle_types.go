package smartidle

import (
	"sync"
	"time"
)

var TIME_INTV int = 1000 //timeout interval //periodic timer

type ClientInfo struct {
	Seq     int
	Digits  string
	Oldtime time.Time
}
type Templ struct {
	Seq          int
	Str_conf     string
	Success_flag string
}

type Idle_s struct {
	IDLE_DIR   string
	RESET      string
	NGX_PATH   string
	CACHE_DIR  string
	AUTO_CONF  string
	MAP_TTL    int
	CERT_PATH  string
	AGENT_PORT string

	MODE int // parking proxy(1), nginx idle(0)

	Imgpath string //captcha

	TargetIP  string
	PublicIP  string
	HttpProxy string // http target ip, target port
	TcpProxy  string // tcp target ip, target port

	NodeID    int
	Port_myip string
	//	iTargetIP, iListenIP uint32
}

//////////////////////////////////////////////
var domain_idx = make(map[string]int)

//map
type NgxconfInfo struct { //for map
	sync.RWMutex
	Domain_m map[string]Dominfo
}

//type NgxconfInfo_Client struct { //for map non agent

type Dominfo struct { // / key: domain(string type)
	Dom_ver string
	Ips_ver string
	Wf_ver  string
	Intime  time.Time

	Status string //"positive" or "negative"

	Blk_http string
	Blk_str  string

	AgentType string // nonagent, agent (securepath type)

	//Port int
}
