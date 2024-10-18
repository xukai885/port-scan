package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"port-scan/alert"
	"strings"
	"sync"
	"time"
)

type ResJson struct {
	CloseNum ClosePort `json:"close"`
	OpenNum  OpenPort  `json:"open"`
}

type OpenPort struct {
	OpenPortHost []string `json:"OpenHostPort"`
}

type ClosePort struct {
	ClosePortHost []string `json:"CloseHostPort"`
}

var (
	ClosePortHost []string     // 检测端口关闭的IP
	OpenPortHost  []string     // 检测端口打开的IP
	ipList        []string     // ip地址列表
	portList      []string     // 端口列表
	ipListMux     sync.RWMutex // 保护ipList的读写锁
	portListMux   sync.RWMutex
)

//go:embed templates/*
var indexHTML embed.FS
var tmpl *template.Template

//go:embed templates/Link.gif
var favicon []byte

func main() {

	// 解析嵌入的模板
	var err error
	tmpl, err = template.ParseFS(indexHTML, "templates/index.html")
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	done := make(chan bool)
	go func() {
		for {
			select {
			case <-ticker.C:
				// 在这里放置定时任务要执行的代码
				alert.ScanOpen(OpenPortHost)
			case <-done:
				return
			}
		}
	}()

	// 路由设置
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/favicon.gif", faviconHandler)
	http.HandleFunc("/scan", scanHandler)                          // 添加扫描器
	http.HandleFunc("/api/results", resultsHandler)                // 扫描结果
	http.HandleFunc("/api/get-ips", getIPsHandler)                 // 获取当前IP列表
	http.HandleFunc("/api/add-ip", addIPHandler)                   // 添加IP
	http.HandleFunc("/api/delete-ip", deleteIPHandler)             // 删除IP
	http.HandleFunc("/api/get-ports", getPortsHandler)             // 获取端口列表
	http.HandleFunc("/api/add-port", addPortHandler)               // 添加端口
	http.HandleFunc("/api/delete-port", deletePortHandler)         // 删除端口
	http.HandleFunc("/api/get-alert", alert.GetAlertHandler)       //查看静默告警规则
	http.HandleFunc("/api/add-alert", alert.AddAlertHandler)       // 添加告警屏蔽
	http.HandleFunc("/api/delete-alert", alert.DeleteAlertHandler) // 删除告警屏蔽
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	// 启动服务器
	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))

}
func faviconHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/gif")
	w.Write(favicon)
}

// 首页处理器
func indexHandler(w http.ResponseWriter, r *http.Request) {
	//tmpl := template.Must(template.ParseFiles("templates/index.html"))
	//tmpl.Execute(w, nil)
	err := tmpl.Execute(w, nil) // 你可以替换 nil 为需要传递的数据
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Template execution error: %v", err)
	}
}

// 处理扫描请求
func scanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		log.Println("Invalid request method")
		return
	}

	log.Println("开始处理")

	if len(ipList) != 0 {
		http.Error(w, "定时任务已存在", http.StatusBadRequest)
		log.Println("定时任务已存在")
		return
	}

	// 解析表单
	r.ParseForm()
	ips := r.FormValue("ips")
	ports := r.FormValue("ports")
	period := r.FormValue("period")

	// 处理输入
	ipList = strings.Split(ips, ",")
	portList = strings.Split(ports, ",")

	// 设置定时扫描
	duration, err := time.ParseDuration(period + "s")
	if err != nil {
		http.Error(w, "Invalid period format", http.StatusBadRequest)
		return
	}

	// 开启协程进行扫描
	go startScanning(ipList, portList, duration)

	// 重定向到结果展示页面
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func startScanning(ipListold, portListold []string, interval time.Duration) {
	// 保证第一次运行
	log.Println("run first scan ... ...")
	scanPorts(ipListold, portListold)

	for {
		// 检查ipList和portList是否为空
		ipListMux.Lock()
		portListMux.Lock()

		// 如果两个列表都为空，退出定时器
		if len(ipList) == 0 && len(portList) == 0 {
			portListMux.Unlock()
			ipListMux.Unlock()
			log.Println("ipList和portList为空，停止定时器。")
			return // 退出函数，终止定时器
		}

		// 更新ipListold和portListold为当前的ipList和portList
		ipListold = ipList
		portListold = portList

		portListMux.Unlock()
		ipListMux.Unlock()

		// 扫描端口
		log.Println("run scan ... ...")
		scanPorts(ipListold, portListold)

		// 定时等待下次扫描
		time.Sleep(interval)
	}
}

// 扫描端口的函数，封装起来
func scanPorts(ipList, portList []string) {
	var closeporthost []string
	var openporthost []string

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, ip := range ipList {
		for _, port := range portList {
			wg.Add(1)
			go func(ip, port string) {
				defer wg.Done()
				addr := fmt.Sprintf("%s:%s", strings.TrimSpace(ip), strings.TrimSpace(port))
				log.Println("Scanning", addr)
				conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
				if err != nil {
					mu.Lock()
					closeporthost = append(closeporthost, fmt.Sprintf("%s:%s", ip, port))
					mu.Unlock()
				} else {
					conn.Close()
					mu.Lock()
					openporthost = append(openporthost, fmt.Sprintf("%s:%s", ip, port))
					mu.Unlock()
				}
			}(ip, port)
		}
	}

	// 等待所有 goroutine 完成
	wg.Wait()

	// 使用锁保护共享资源
	ipListMux.Lock()
	portListMux.Lock()
	OpenPortHost = openporthost
	ClosePortHost = closeporthost
	portListMux.Unlock()
	ipListMux.Unlock()
}

// 返回扫描结果的JSON接口
func resultsHandler(w http.ResponseWriter, r *http.Request) {
	// 创建 ResJson 实例
	response := ResJson{
		OpenNum: OpenPort{
			OpenPortHost: OpenPortHost,
		},
		CloseNum: ClosePort{
			ClosePortHost: ClosePortHost,
		},
	}

	// 设置响应头
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// 将响应数据编码为 JSON
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// 获取IP列表的处理器
func getIPsHandler(w http.ResponseWriter, r *http.Request) {
	ipListMux.RLock()
	defer ipListMux.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ipList)
}

// 获取port列表的处理器
func getPortsHandler(w http.ResponseWriter, r *http.Request) {
	portListMux.RLock()
	defer portListMux.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(portList)
}

// 添加IP的处理器
func addIPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	ips := r.FormValue("ip")

	if ips != "" {
		// 取出ip
		addips := strings.Split(ips, ",")
		ipListMux.Lock()
		// 使用 ... 将切片解包并追加到 ipList
		ipList = append(ipList, addips...)
		ipListMux.Unlock()
		//fmt.Fprintf(w, "IP added: %s", addips)
		log.Println("添加IP:", addips)
	} else {
		http.Error(w, "IP is required", http.StatusBadRequest)
	}
}

// 删除IP的处理器
func deleteIPHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	ip := r.FormValue("ip")
	if ip == "" {
		http.Error(w, "IP is required", http.StatusBadRequest)
		return
	}

	ipListMux.Lock()
	defer ipListMux.Unlock()

	// 查找并删除IP
	for i, storedIP := range ipList {
		if storedIP == ip {
			ipList = append(ipList[:i], ipList[i+1:]...)
			fmt.Fprintf(w, "IP deleted: %s", ip)
			log.Println("删除IP:", ip)
			return
		}
	}
	http.Error(w, "IP not found", http.StatusNotFound)
}

// 删除port的处理器
func deletePortHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	port := r.FormValue("port")
	if port == "" {
		http.Error(w, "Port is required", http.StatusBadRequest)
		return
	}

	portListMux.Lock()
	defer portListMux.Unlock()

	// 查找并删除IP
	for i, storedPort := range portList {
		if storedPort == port {
			portList = append(portList[:i], portList[i+1:]...)
			//fmt.Fprintf(w, "IP deleted: %s", ip)
			log.Println("删除Port:", port)
			return
		}
	}
	http.Error(w, "Port not found", http.StatusNotFound)
}

// 添加port的处理器
func addPortHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	ports := r.FormValue("port")

	if ports != "" {
		// 取出port
		addports := strings.Split(ports, ",")
		portListMux.Lock()
		// 使用 ... 将切片解包并追加到 portList
		portList = append(portList, addports...)
		portListMux.Unlock()
		log.Println("添加ports:", addports)
	} else {
		http.Error(w, "Port is required", http.StatusBadRequest)
	}
}
