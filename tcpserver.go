/*****************************************************************************************************************************************
 * server和client 长链接通信功能，逻辑有交换密钥，登录，登出，心跳，push,feedback
 * liqingfang
 * 2018.8.5
**************************************************************************************************************************************************/

package main

import (
	"encoding/json"
	"net"
	"lib/crypto"
	"lib/logger"
	"lib/panhead"
	"runtime"
	"time"
)

const ConnectionInit = 1
const ConnectionTransmitKey = 2
const ConnectionLogin = 3
const ConnectionHeartbeat = 4

var errBuf = make([]byte, 1024)

/**
 * [TcpListen 监听底层服务，接收端请求]
 */
func TcpListen() {
	var tcpAddr *net.TCPAddr
	tcpAddr, _ = net.ResolveTCPAddr("tcp", "0.0.0.0:"+connectorCfg.TcpServerPort)

	tcpListener, _ := net.ListenTCP("tcp", tcpAddr)
	logger.Info("Tcp Server listen : " + connectorCfg.LocalIp + ":" + connectorCfg.TcpServerPort)

	defer tcpListener.Close()

	for {
		tcpConn, err := tcpListener.AcceptTCP()
		if err != nil {
			continue
		}

		logger.Info("A client connected : " + tcpConn.RemoteAddr().String())
		go tcpPipe(tcpConn)
	}
}

/**
* [tcpPipe ]
* @param  {[type]} tcpConn *net.TCPConn  [description]
* @return {[type]}         [分析和端交互的具体报文]
* 1. 一个协程负责读，拿到数据后go一个协程负责分析数据报头，然后再go一个协程负责写。之间无数据阻塞，和端在没有网络交互时，server保持一个client一个goroutine。
  2. 如果后期存在goroutine巨多影响单机性能时，可采用每个连接3个协程处理，通过channel通信，但有一定数据阻塞。
   new(connection)如果后期存在频繁创建回收，可引入内存池，结构体中含有channel变量conn.msgAck需单独再申请空间
*/
func tcpPipe(tcpConn *net.TCPConn) {
	conn := new(connection)
	conn.tcpConn = tcpConn
	conn.status = ConnectionInit
	conn.deviceId = ""
	conn.msgAck = make(chan uint32, 1)

	defer cleanConn(conn)

	tmpBuffer := make([]byte, 0)
	buffer := make([]byte, 1024)
	onePacketBody := make([]byte, 1024)
	bodyOverFlag := true
	objPanHead := new(panhead.PanHead)

	for {
		//timeoutSec := time.Second * connectorCfg.HeartbeatInterval
		timeoutSec := time.Second * 70
		timeout := time.Now().Add(timeoutSec)
		conn.tcpConn.SetReadDeadline(timeout)

		n, err := conn.tcpConn.Read(buffer)
		if err != nil {
			logger.Warn(conn.tcpConn.RemoteAddr().String(), " connection error: ", err, " deviceId: ", conn.deviceId)
			return
		}

		tmpBuffer = append(tmpBuffer, buffer[:n]...)

		if bodyOverFlag {
			if len(tmpBuffer) < panhead.PanHeadLength {
				continue
			}

			tmpBuffer = objPanHead.ReadHeader(tmpBuffer)
			if objPanHead.MagicNum != panhead.DefaultMagicNum {
				logger.Warn("magic num not equal")
				return
			}

			if uint32(len(tmpBuffer)) < objPanHead.BodyLen {
				bodyOverFlag = false
				continue
			}
		} else {
			if uint32(len(tmpBuffer)) < objPanHead.BodyLen {
				continue
			}
		}

		bodyOverFlag = true
		onePacketBody = tmpBuffer[:objPanHead.BodyLen]
		tmpBuffer = tmpBuffer[objPanHead.BodyLen:]
		go processBody(conn, objPanHead, onePacketBody)
	}
}

/******************************************************************************
1. 本函数内不能使用defer cleanConn(conn) 否则goroutine后连接直接关闭
******************************************************************************/
func processBody(conn *connection, objPanHead *panhead.PanHead, onePacketBody []byte) {
	ok := false
	msgType := -1

	//defer是函数退出必执行
	defer getPanicError()

	//心跳包
	if objPanHead.PacketType == 0x01 {
		go connAckHeartbeat(conn, objPanHead)
	} else {
		bodyMap := make(map[string]interface{})
		//根据header头判断是否为交换秘钥阶段
		if objPanHead.PacketType == 0x03 {
			origData, errRsa := crypto.RsaDecrypt(onePacketBody, connectorCfg.PrivateKey)
			if errRsa != nil {
				logger.Warn("RsaDecrypt error:", errRsa)
				cleanConn(conn)
				return
			}
			errJson := json.Unmarshal(origData, &bodyMap)
			if errJson != nil {
				logger.Warn("Json.unmarshal error:", errJson)
				cleanConn(conn)
				return
			}
			conn.secretKey, ok = bodyMap["data"].(string)
			if !ok {
				logger.Warn("bodyMap secretKey data error:", bodyMap)
				cleanConn(conn)
				return
			}

			logger.Info(" secretKey bodyMap: ", bodyMap)
			go connAckSecretKeyReceive(conn, objPanHead.Id)

		} else {
			//上下线或者feedback
			if string(conn.secretKey) == "" {
				logger.Warn("secretKey null objPanHead.PacketType ", objPanHead.PacketType)
				cleanConn(conn)
				return
			}
			origData2, errDes := crypto.DesDecrypt(onePacketBody, []byte(conn.secretKey))
			if errDes != nil {
				logger.Warn("DesDecrypt error:", errDes)
				cleanConn(conn)
				return
			}
			errJson := json.Unmarshal(origData2, &bodyMap)
			if errJson != nil {
				logger.Warn("Json.unmarshal error:", errJson)
				cleanConn(conn)
				return
			}

			//考虑到数据拷贝，不单独调用函数 analyseBody
			conn.deviceId, ok = bodyMap["deviceId"].(string)
			if !ok {
				logger.Warn("bodyMap deviceId data error:", bodyMap)
				cleanConn(conn)
				return
			}

			_, ok = bodyMap["clientType"]
			if !ok {
				logger.Warn("bodyMap clientType data error:", bodyMap)
				cleanConn(conn)
				return
			}
			conn.clientType = uint8(bodyMap["clientType"].(float64))

			_, ok = bodyMap["msgType"]
			if !ok {
				logger.Warn("bodyMap msgType data error:", bodyMap)
				cleanConn(conn)
				return
			}
			msgType = int(bodyMap["msgType"].(float64))

			if msgType == 3 {
				conn.version, ok = bodyMap["version"].(string)
				if !ok {
					logger.Warn("bodyMap version data error:", bodyMap)
					cleanConn(conn)
					return
				}
			}

			switch msgType {
			case 3:
				go connAckLogin(conn, objPanHead.Id)
			case 4:
				go connAckLogout(conn, objPanHead.Id)
			case 6:
				go connPushFeedback(conn, objPanHead.Id, string(origData2))
			default:
				logger.Warn("Wrong msgType bodyMap is ", bodyMap)
			}
		}
	}
}

/*
func analyseBody(bodyMap map[string]interface{}, conn *connection) (msgType int) {
    var exists bool

    RETURN:
    logger.Warn("analyseBody data error:", bodyMap)
    cleanConn(conn)
    return -1

    conn.deviceId, exists = bodyMap["deviceId"].(string)
    if !exists {
       goto RETURN
    }

    conn.clientType, exists = bodyMap["clientType"].(string)
    if !exists {
        goto RETURN
    }

    msgType, exists := int(bodyMap["msgType"].(float64))
    if !exists {
        goto RETURN
    } else {
        if (msgType == 3) {
            conn.version, exists = bodyMap["version"].(string)
            if !exists {
                goto RETURN
            }
        }
    }

    return msgType
}
*/

func getPanicError() {
	if err := recover(); err != nil {
		n := runtime.Stack(errBuf, false)
		logger.Warn("err:%s, stack:%s", err, errBuf[:n])
	}
}

//读写超时以及异常，统一请求该函数，做资源回收和状态标记
func cleanConn(conn *connection) {
	/*
	   close(conn.msgAck)
	   x, ok := <-conn.msgAck
	   if ok != false {
	       logger.Warn(conn.tcpConn.RemoteAddr().String(), "conn.msgAck close err new val: ", x)
	   }
	*/

	conn.tcpConn.Close()
	getPanicError()

	if conn.deviceId != "" {
		sendProxyOnline(0, conn)
		_, ok := ConnInfoMap[conn.deviceId]
		if ok {
			ConnInfoMapMutex.Lock()
			delete(ConnInfoMap, conn.deviceId)
			OnlineClientCount--
			ConnInfoMapMutex.Unlock()
		}
	}

	logger.Info("disconnected :"+conn.tcpConn.RemoteAddr().String()+" deviceId: ", conn.deviceId)
}

func sendProxyOnline(online uint8, conn *connection) {

	for i := 0; i < 3; i++ {
		var err error

		prefix := "n-clouddisk-push-"
		hkey := prefix + conn.deviceId

		err = RedisClient.HMSet(hkey, "online", online, "conip", connectorCfg.LocalIp, "conport", connectorCfg.TcpServerPort, "version", conn.version)
		if err != nil {
			logger.Warn("Redis hmset error. retryTime: %d. err: %s", i, err.Error())
		}

		if err == nil {
			logger.Info("Update Deviceid: %d Status Succfully", conn.deviceId)
			return
		}
	}

	logger.Warn("Update Deviceid: %d Status Fail", conn.deviceId)
}

func connAckLogin(conn *connection, id uint32) {
	conn.status = ConnectionLogin
	conn.LoginTime = time.Now().Unix()
	logger.Info("connAckLogin deviceId: ", conn.deviceId, " id: ", id)

	resPanHead := new(panhead.PanResHead)
	resPanHead.ErrorNo = 0
	resPanHead.Version = 1
	resPanHead.PacketType = 2
	resPanHead.MagicNum = panhead.DefaultMagicNum
	resPanHead.Reserved = 0
	resPanHead.BodyLen = 0
	resPanHead.Id = id
	resPanHead.Conn = conn.tcpConn

	timeoutSec := time.Second * 5
	timeout := time.Now().Add(timeoutSec)
	conn.tcpConn.SetWriteDeadline(timeout)

	b := make([]byte, 0)
	_, err := resPanHead.Write(b)

	if err != nil {
		logger.Warn("connAckLogin write err deviceId: ", conn.deviceId, " err: ", err)
		cleanConn(conn)
		return
	}

	ConnInfoMapMutex.Lock()
	ConnInfoMap[conn.deviceId] = conn
	OnlineClientCount++
	ConnInfoMapMutex.Unlock()

	//todo 如果存在严重阻塞，可以单独启动goroutine
	sendProxyOnline(1, conn)

	_, ok := ConnInfoMap[conn.deviceId]
	if !ok {
		logger.Warn("get map deviceId error ", conn.deviceId)
		cleanConn(conn)
		return
	}

	logger.Info("connAckLogin deviceId over ", conn.deviceId)
}

/**
 * [connAckLogout description]
 * @param  {[type]} conn *connection   [description]
 * @param  {[type]} id   uint32        [description]
 * @return {[type]}      [description]
 */
func connAckLogout(conn *connection, id uint32) {
	logger.Info("connAckLogout deviceId: ", conn.deviceId, " id: ", id)

	resPanHead := new(panhead.PanResHead)
	resPanHead.ErrorNo = 0
	resPanHead.Version = 1
	resPanHead.PacketType = 2
	resPanHead.MagicNum = panhead.DefaultMagicNum
	resPanHead.Reserved = 0
	resPanHead.BodyLen = 0
	resPanHead.Id = id
	resPanHead.Conn = conn.tcpConn

	timeoutSec := time.Second * 5
	timeout := time.Now().Add(timeoutSec)
	conn.tcpConn.SetWriteDeadline(timeout)

	b := make([]byte, 0)
	_, err := resPanHead.Write(b)

	if err != nil {
		logger.Warn("connAckLogout write err deviceId: ", conn.deviceId, " err: ", err)
	}

	cleanConn(conn)
}

/**
 * [connPushFeedback description]
 * @param  {[type]} conn *connection   [description]
 * @param  {[type]} id   uint32        [下发消息的id]
 * @return {[type]}      [description]
 */
func connPushFeedback(conn *connection, id uint32, feedback string) {
	feedbackTime := time.Now().UnixNano() / 1000000
	logger.Info("Pushid: %d, feedbackMsg: %s, feedbackTime: %d", id, feedback, feedbackTime)

	conPtr, ok := ConnInfoMap[conn.deviceId]
	if ok {
		conPtr.msgAck <- id
	}

	logger.Info("connPushFeedback ack over")
}

/**
 * [connAckHeartbeat description]
 * @param  {[type]} conn       *connection      [description]
 * @param  {[type]} objPanHead *panhead.PanHead [description]
 * @return {[type]}            [description]
 */
func connAckHeartbeat(conn *connection, objPanHead *panhead.PanHead) {
	logger.Info("Get connAckHeartbeat version, deviceId ", objPanHead.Version, conn.deviceId, " RemoteAddr: ", conn.tcpConn.RemoteAddr().String(), " objPanHead.Id: ", objPanHead.Id)
	conn.lastActiveTime = time.Now().Unix()
	conn.status = ConnectionHeartbeat

	resPanHead := new(panhead.PanResHead)
	resPanHead.ErrorNo = 0
	resPanHead.Version = objPanHead.Version //不要修改version取值
	resPanHead.PacketType = 1
	resPanHead.MagicNum = panhead.DefaultMagicNum
	resPanHead.Reserved = 0
	resPanHead.BodyLen = 0
	resPanHead.Id = objPanHead.Id
	resPanHead.Conn = conn.tcpConn

	timeoutSec := time.Second * 5
	timeout := time.Now().Add(timeoutSec)
	conn.tcpConn.SetWriteDeadline(timeout)

	b := make([]byte, 0)
	_, err := resPanHead.Write(b)

	if err != nil {
		logger.Warn("connAckHeartbeat write err deviceId: ", conn.deviceId, " err: ", err)
		cleanConn(conn)
	}
}

/**
 * [connAckSecretKeyReceive description]
 * @param  {[type]} conn *connection   [description]
 * @param  {[type]} id   uint32        [description]
 * @return {[type]}      [description]
 */
func connAckSecretKeyReceive(conn *connection, id uint32) {
	var errorNo uint16 = 0
	//过载保护，让端感知
	if len(ConnInfoMap) == connectorCfg.DefaultConnectionSize {
		errorNo = 1
	}
	//服务重启时，主动关闭连接
	if restartFlag == true {
		errorNo = 1
	}

	logger.Info("connAckSecretKeyReceive: ", conn, " id: ", id)
	conn.status = ConnectionTransmitKey

	ackBodyMap := make(map[string]interface{})
	ackBodyMap["msgType"] = 2
	ackBodyMap["data"] = conn.secretKey
	ackBodyStr, _ := json.Marshal(ackBodyMap)
	result, _ := crypto.DesEncrypt([]byte(ackBodyStr), []byte(conn.secretKey))

	resPanHead := new(panhead.PanResHead)
	resPanHead.ErrorNo = errorNo
	resPanHead.Version = 1
	resPanHead.PacketType = 2
	resPanHead.MagicNum = panhead.DefaultMagicNum
	resPanHead.Reserved = 0
	resPanHead.BodyLen = uint32(len(result))
	resPanHead.Id = id
	resPanHead.Conn = conn.tcpConn

	timeoutSec := time.Second * 5
	timeout := time.Now().Add(timeoutSec)
	conn.tcpConn.SetWriteDeadline(timeout)

	total := len(result) + panhead.PanResHeadLength
	n, err := resPanHead.Write(result)
	if err != nil {
		logger.Warn("connAckSecretKeyReceive write err: ", err)
		cleanConn(conn)
	}

	logger.Info("connAckSecretKeyReceive Send total %d write count %d Write %s ", total, n, ackBodyStr)

	if errorNo == 1 {
		cleanConn(conn)
	}
}
