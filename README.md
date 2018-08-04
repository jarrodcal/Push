===
#消息推送系统
使用Go开发，充分利用goroutine解决和客户端海量连接问题，较比C语言实现的Push，系统易设计和维护。

## 系统设计：
* 1 系统整体上有4类goroutine：
一类接收上游待推送数据，一类监听客户端连接，一类定时关闭已断线连接，一类统计系统状态。
新的连接过来，监听客户端协程会继续派生出一个goroutine，每个客户端都有一个协程和其交互。单机的协程数目约等于连接数目。
* 2 和客户端交互采用RSA验证身份和交换密钥，AES加密后续通信数据，业务流程上包括上线、下线、心跳、推送、推送反馈。
* 3 和端保持的协程会一直读取端是否有数据过来，当发送数据过来会派生出一个goroutine负责分析数据包，判断出哪种业务包，然后再由这个goroutine继续派生出一个协程，负责写数据给端上。和端通信上没有阻塞，一个协程一直负责读，一个协程负责分析报文，一个负责写。当端源源不断上行数据时，一个连接会存在3个协程。
* 4 Server和客户端的通信协议为二进制，包含协议版本号、此次通信id、消息类型、防篡改数值、数据包大小等字段。
* 5 客户端连接会存储在一个全局的map表中，以端的设备ID为key，value为该连接有关信息的指针，具体数据结构：
type connection struct {
	* tcpConn        *net.TCPConn
	* secretKey      string
	* version        string
	* deviceId       string
	* loginTime      int64
	* lastActiveTime int64
	* status         uint8
	* clientType     uint8
	* msgAck         chan uint32
* }


## 架构图：
* 业务层：消息分发API
* 接口层：在线状态查询、消息组装、设备管理
* 通讯层：协议解析、Push下发、Session管理
* 设备层：客户端

## 待跟进：
* 1 存在goroutine巨多影响单机性能时，处理连接数据部分可引入消息队列模式。
* 2 new(connection)如果后期存在频繁创建、回收，可引入内存池。
