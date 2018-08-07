package main

import (
	"fmt"
	"github.com/robfig/config"
	"net"
	"os"
	"lib/logger"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	CONN_CHECK_INTERVAL = 60 * 5
	CONN_DEAD_THRESHOLD = 60 * 2
)

var privateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
11111111111111111111111111111111111111111111111111111111111
11111111111111111111111111111111111111111111111111111111111
-----END RSA PRIVATE KEY-----
`)

var publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
22222222222222222222222222222222222222222222222222222222222
22222222222222222222222222222222222222222222222222222222222
-----END PUBLIC KEY-----
`)

type ConnectorCfg struct {
	ProxyServerPort       string
	ApiServerPort         string
	TcpServerPort         string
	DefaultConnectionSize int
	LogFile               string
	LogLevel              int
	ProxyHost             string
	ProxyBns              string
	RedisBns              string
	MaxConnectionSize     int
	StateInfoInterval     int
	LocalIp               string
	PingInterval          int
	PingTimeout           int
	HeartbeatInterval     int
	PublicKey             []byte
	PrivateKey            []byte
}

type connection struct {
	tcpConn        *net.TCPConn
	secretKey      string
	version        string
	deviceId       string
	LoginTime      int64
	lastActiveTime int64
	status         uint8
	clientType     uint8
	msgAck         chan uint32
}

var ConnInfoMap map[string]*connection
var ConnInfoMapMutex = &sync.RWMutex{}
var connectorCfg = &ConnectorCfg{}
var restartFlag bool
var OnlineClientCount uint32

func InitAll() {
	c, err := config.ReadDefault("./conf/Connector.cfg")
	if err != nil {
		fmt.Println(err)
		panic("init config failed")
	}

	connectorCfg.ProxyServerPort, _ 		= c.String("Server", "ProxyServerPort")
	connectorCfg.ApiServerPort, _ 			= c.String("Server", "ApiServerPort")
	connectorCfg.TcpServerPort, _ 			= c.String("Server", "TcpServerPort")
	connectorCfg.LogFile, _ 			= c.String("Log", "LogFile")
	connectorCfg.LogLevel, _ 			= c.Int("Log", "LogLevel")
	connectorCfg.DefaultConnectionSize, _ 		= c.Int("Server", "DefaultConnectionSize")
	connectorCfg.MaxConnectionSize, _ 		= c.Int("Server", "MaxConnectionSize")
	connectorCfg.StateInfoInterval, _ 		= c.Int("Server", "StateInfoInterval")
	connectorCfg.PingInterval, _ 			= c.Int("Server", "PingInterval")
	connectorCfg.PingTimeout, _ 			= c.Int("Server", "PingTimeout")
	connectorCfg.HeartbeatInterval, _ 		= c.Int("Server", "HeartbeatInterval")
	connectorCfg.PublicKey 				= publicKey
	connectorCfg.PrivateKey 			= privateKey
	connectorCfg.LocalIp, _ 			= GetLocalHostIp()

	logger.Init("Connector", connectorCfg.LogLevel, connectorCfg.LogFile)
	restartFlag = false
	OnlineClientCount = 0

	InitBnsMap()
	InitRedisClient(connectorCfg.RedisBns)
}

//获取本机ip
func GetLocalHostIp() (ip string, err error) {
	list, err := net.Interfaces()
	if err != nil {
		return
	}
	//xgbe0
	for _, iface := range list {
		ethname := strings.Trim(iface.Name, " ")
		ethname = strings.ToLower(ethname)
		if ethname != "eth0" && ethname != "eth1" && ethname != "xgbe0" {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return "", nil
		}

		for _, addr := range addrs {

			ipinfo := strings.Split(addr.String(), "/")
			if len(ipinfo) > 0 {
				ip = ipinfo[0]
				return ip, nil
			}
		}
	}

	return "", nil
}

func Watching() {
	t := time.Tick(time.Second * 2)
	for {
		select {
		case <-t:
			logger.Info("GoroutineCount: %d, OnlineClientCount %d, TotalCount %d", runtime.NumGoroutine(), OnlineClientCount, connectorCfg.DefaultConnectionSize)
		}
	}
}

func closeDeadConn() {
	t := time.Tick(time.Second * CONN_CHECK_INTERVAL)
	for {
		currTimestamp := time.Now().Unix()
		select {
		case <-t:
			for deviceId, conn := range ConnInfoMap {
				if currTimestamp-(*conn).lastActiveTime > CONN_DEAD_THRESHOLD {
					logger.Info("Dead Connection. Deviceid: %s, LoginTime: %d, LastActiveTime: %d", deviceId, (*conn).LoginTime, (*conn).lastActiveTime)
					ConnInfoMapMutex.Lock()
					delete(ConnInfoMap, deviceId)
					ConnInfoMapMutex.Unlock()
				}
			}
		}
	}
}

func main() {
	cpus := runtime.NumCPU()
	if cpus > 1 {
		cpus -= 1
	}
	runtime.GOMAXPROCS(cpus)

	//监听golang 的状态
	go profileInfo()
	go Watching()

	//参数初始化，需要注意ProxyServerPort的初始化
	InitAll()

	if connectorCfg.LocalIp == "" {
		logger.Critical("Get ip error")
		return
	}

	ConnInfoMap = make(map[string]*connection, connectorCfg.DefaultConnectionSize)

	//接收后端请求
	go ApiListen()

	//长连接
	go TcpListen()

	go closeDeadConn()

	//接收到关闭服务信号
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	logger.Critical("Get signal begin quit......", <-ch)

	//主动关闭正在请求的连接
	restartFlag = true

	//关闭已经建立的连接
	for deviceId, connPtr := range ConnInfoMap {
		connPtr.tcpConn.Close()

		if deviceId != "" {
			sendProxyOnline(0, connPtr)
			ConnInfoMapMutex.Lock()
			delete(ConnInfoMap, deviceId)
			OnlineClientCount--
			ConnInfoMapMutex.Unlock()
		}

		logger.Info("disconnected :" + connPtr.tcpConn.RemoteAddr().String())
	}

	logger.Critical("Connector quit over")
}
