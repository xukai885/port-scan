package alert

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"
)

var noalertList []string

func ScanOpen(OpenPortHost []string) {
	// 剔除静默告警信息
	OpenPortHost = filterOpenPortHost(OpenPortHost, noalertList)
	if len(OpenPortHost) == 0 {
		log.Println("暂无告警信息")
	} else {
		err := sendAlert("01bd83f16704c5d9115526b2ea0d6caf0170471474847c05c5e544a538fbe8b2", time.Now().UnixNano()/int64(time.Millisecond), "SEC1d8ef895c9dc237263a6a7047c848cbc729d7cbd84c51fe3d83134e857482d9a", msgMarkdown(OpenPortHost))
		if err != nil {
			log.Println("sendAlert err:", err)
			return
		}
	}
}

func msgMarkdown(OpenPortHost []string) (msg string) {
	for _, ip := range OpenPortHost {
		msg = fmt.Sprintf("%s\n%s", msg, ip)
	}
	nowTime := time.Now().Format("2006-01-02 15:04:05")
	msg = fmt.Sprintf("## %s \n## OpenPortHost Info:\n```%s", nowTime, msg)
	return
}

func sendAlert(accessToken string, timestamp int64, secret string, msg string) (err error) {
	sign, err := generateSignature(secret, timestamp)
	if err != nil {
		return
	}
	url := fmt.Sprintf("https://oapi.dingtalk.com/robot/send?access_token=%s&timestamp=%d&sign=%s", accessToken, timestamp, sign)
	payload := map[string]interface{}{
		"msgtype": "markdown",
		"markdown": map[string]string{
			"title": "OpenPortHost Info",
			"text":  msg,
		},
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return
	}

	log.Println(url)
	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// 打印响应体
	fmt.Println("Response Body:", string(body))

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send alert, status: %s", resp.Status)
	}

	return nil
}

func generateSignature(secret string, timestamp int64) (string, error) {
	signature := fmt.Sprintf("%d\n%s", timestamp, secret)
	h := hmac.New(sha256.New, []byte(secret))
	_, err := h.Write([]byte(signature))
	if err != nil {
		return "", err
	}

	base64Signature := base64.StdEncoding.EncodeToString(h.Sum(nil))
	encodedSignature := url.QueryEscape(base64Signature)

	return encodedSignature, nil
}

func filterOpenPortHost(openPortHost, noalertList []string) []string {
	// 将 noalertList 转换为 map，便于快速查找
	noalertMap := make(map[string]struct{})
	for _, item := range noalertList {
		noalertMap[item] = struct{}{}
	}

	// 遍历 OpenPortHost，保留不在 noalertMap 中的元素
	var filteredList []string
	for _, host := range openPortHost {
		if _, found := noalertMap[host]; !found {
			filteredList = append(filteredList, host)
		}
	}

	return filteredList
}

// AddAlertHandler 添加告警屏蔽
func AddAlertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	iport := r.FormValue("iport")

	if iport != "" {
		noalertList = append(noalertList, iport)
		log.Println("添加告警静默:", iport)
	} else {
		http.Error(w, "iport is nil", http.StatusBadRequest)
	}

}

// GetAlertHandler 静默告警规则
func GetAlertHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(noalertList)
}

// DeleteAlertHandler 删除告警规则
func DeleteAlertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	iport := r.FormValue("iport")

	if iport != "" {
		noalertList = removePort(noalertList, iport)

		log.Println("删除告警静默:", iport)
	} else {
		http.Error(w, "iport is nil", http.StatusBadRequest)
	}
}

func removePort(list []string, port string) []string {
	for i, v := range list {
		if v == port {
			// 删除端口，返回更新后的切片
			return append(list[:i], list[i+1:]...)
		}
	}
	return list // 如果没有找到，返回原切片
}
