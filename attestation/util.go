package attestation

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"strings"
)

func SendMessage(conn net.Conn, message string) {
	messageBytes := []byte(message)
	length := len(messageBytes)
	// 先发送长度
	// conn.Write([]byte(fmt.Sprintf("%d\n", length)))
	conn.Write([]byte{byte(length >> 8), byte(length)})
	conn.Write(messageBytes)
}

func ReceiveMessage(conn net.Conn) string {
	// 先读取长度
	lengthBuf := make([]byte, 2) // 假定长度不会超过16字节
	conn.Read(lengthBuf)

	length := int(lengthBuf[0])<<8 | int(lengthBuf[1])

	// 读取消息内容
	data := make([]byte, length)
	conn.Read(data)
	return string(data)
}

func SendFile(conn net.Conn, filePath string) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	length := len(data)
	conn.Write([]byte{byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)})
	conn.Write(data)
}

func ReceiveFile(conn net.Conn, filePath string) {
	// 先读取文件长度
	buf := make([]byte, 4)
	conn.Read(buf)
	length := int(buf[0])<<24 | int(buf[1])<<16 | int(buf[2])<<8 | int(buf[3])
	data := make([]byte, length)
	conn.Read(data)
	ioutil.WriteFile(filePath, data, 0644)
}

/* Read the pubkey from the pem.file in certain format */
func ExtractPubkeyFromPem(pubkey string) string {
	// Remove all newline characters and split lines
	lines := strings.Split(pubkey, "\n")

	// Filter the lines, ignoring BEGIN and END lines
	var cleanedLines []string
	for _, line := range lines {
		if strings.HasPrefix(line, "-----BEGIN") || strings.HasPrefix(line, "-----END") || line == "" {
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}

	// Join the remaining lines back together
	return strings.Join(cleanedLines, "")
}

/* Call openssl to get the pubkey from the certificate */
func CallOpensslGetPubkey(filePath string) string {
	cmd := exec.Command("openssl", "x509", "-in", filePath, "-pubkey", "-noout")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error getting pubkey from certificate", err)
		return ""
	}
	return string(output)
}

/* to get SNP machine attestation JWT */
func CallSNPAttestationClient(nonce string) string {
	cmd := exec.Command("sudo", "AttestationClient", "-n", nonce, "-o", "token")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error calling AttestationClient:", err)
		return ""
	}
	return string(output)
}

/* to get TDX machine attestation JWT */
func CallTDXAttestationClient(nonce string, mma_path string) string {
	nonce = ""
	cmd := exec.Command("sudo", "TdxAttest", "-c", mma_path)
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error calling AttestationClient:", err)
		return ""
	}

	oriOut := string(output)
	startIndex := strings.Index(oriOut, "eyJhb")
	extractedToken := ""
	if startIndex != -1 {
		// 提取从 "eyJhb" 开始到字符串末尾的内容
		extractedToken = oriOut[startIndex:]
		extractedToken = strings.TrimSpace(extractedToken)
		fmt.Println("Extracted JWT Token:")
		fmt.Println(extractedToken)
	} else {
		fmt.Println("JWT Token not found.")
	}
	return extractedToken
}

/* parse JWT into 3 parts */
func ParseJWT(jwtToken string) (*JWTToken, error) {
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	header, payload, signature := parts[0], parts[1], parts[2]

	headerDecoded, err := base64.RawURLEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %v", err)
	}

	payloadDecoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %v", err)
	}

	var token JWTToken
	if err := json.Unmarshal(headerDecoded, &token.Header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %v", err)
	}

	if err := json.Unmarshal(payloadDecoded, &token.Payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload: %v", err)
	}

	token.Signature = signature

	return &token, nil
}

/* extract and check these JWT claims */
func ExtractAndCheckJWTCliams(jwtToken, exptPubKey, exptNonce, exptUserData string) (bool, bool, bool, bool, error) {
	teeType, err := GetPeerTeeType(jwtToken)
	if err != nil {
		fmt.Print("getPeerTeeType failed:", teeType)
		return true, true, true, false, err
	}
	if teeType == "sevsnpvm" {
		return ExtractAndCheck_SNPJWTCliams(jwtToken, exptPubKey, exptNonce, exptUserData)
	}
	if teeType == "tdxvm" {
		return ExtractAndCheck_TDXJWTCliams(jwtToken, exptPubKey, exptNonce, exptUserData)
	}
	return false, false, false, false, fmt.Errorf("unsupported tee type: %s", teeType)
}

/* Currently SNP JWT contains Nonce field */
func ExtractAndCheck_SNPJWTCliams(jwtToken, exptPubKey, exptNonce, exptUserData string) (bool, bool, bool, bool, error) {
	// 1. parse JWT
	token, err := ParseJWT(jwtToken)
	if err != nil {
		return false, false, false, false, err
	}

	// 2.  payload中读 x-ms-isolation-tee.x-ms-compliance-status 的值
	teeComplianceStatus, ok := token.Payload["x-ms-isolation-tee"].(map[string]interface{})["x-ms-compliance-status"].(string)
	checkTee := ok && strings.Contains(teeComplianceStatus, "azure-compliant-cvm")

	// 3. payload中读 x-ms-runtime.client-payload.nonce 的值
	clientPayload, ok := token.Payload["x-ms-runtime"].(map[string]interface{})["client-payload"].(map[string]interface{})
	if !ok {
		return false, false, false, false, fmt.Errorf("missing x-ms-runtime.client-payload.nonce in payload")
	}
	noncePubkey, ok := clientPayload["nonce"].(string)
	if !ok {
		return false, false, false, false, fmt.Errorf("missing x-ms-runtime.client-payload.nonce in payload")
	}
	fmt.Println("NoncePubkey:", noncePubkey)
	// 4. 对 noncePubkey 执行 Base64URL decode
	// noncePubkeyDecode, err := base64.RawURLEncoding.DecodeString(noncePubkey)//for non-padding base64url encoding
	noncePubkeyDecode, err := base64.StdEncoding.DecodeString(noncePubkey)

	if err != nil {
		return false, false, false, false, fmt.Errorf("failed to decode noncePubkey: %v", err)
	}

	tokenNonce := string(noncePubkeyDecode[:12])
	tokenPubkey := string(noncePubkeyDecode[12:])
	checkPubkey := exptPubKey == tokenPubkey
	checkNonce := exptNonce == tokenNonce
	fmt.Println("TeeComplianceStatus:", teeComplianceStatus)
	fmt.Println("Token Nonce:", tokenNonce)
	fmt.Println("Token Pubkey:", tokenPubkey)
	if !checkTee {
		fmt.Println("TeeComplianceStatus is not compliant-cvm")
	}
	if !checkPubkey {
		fmt.Println("Public Key does not match")
	}
	if !checkNonce {
		fmt.Println("Nonce does not match")
	}

	// 5. check user-data field
	// 5.1 read user-data measurement from jwtToken
	userData := ""
	userData, ok = token.Payload["x-ms-isolation-tee"].(map[string]interface{})["x-ms-runtime"].(map[string]interface{})["user-data"].(string)
	if !ok {
		return true, true, true, false, fmt.Errorf("parsing x-ms-isolation-tee.x-ms-runtime.user-data in payload failed")
	}
	exptUserData = strings.ToUpper(exptUserData)
	fmt.Println("UserData measurement:", userData)
	fmt.Println("Expected UserData measurement:", exptUserData)
	checkUserData := exptUserData == userData

	// In test, the userData read from JWT is the same because we are in the same host; but in real env, the userData should be different; The eptUserData is calculated from cert that it is ok
	// remove this line when deploy
	return checkTee, checkPubkey, checkNonce, checkUserData, nil
}

/* Currently TDX JWT contains no Nonce field */
func ExtractAndCheck_TDXJWTCliams(jwtToken, exptPubKey, exptNonce, exptUserData string) (bool, bool, bool, bool, error) {

	// 1. parse JWT
	token, err := ParseJWT(jwtToken)
	if err != nil {
		return false, false, false, false, err
	}

	// 2.  payload中读 x-ms-isolation-tee.x-ms-compliance-status 的值
	teeComplianceStatus, ok := token.Payload["x-ms-compliance-status"].(string)
	checkTee := ok && strings.Contains(teeComplianceStatus, "azure-compliant-cvm")
	// thies two fields are not used in TDX JWT claims chcking; simple set them to true
	checkPubkey := true
	checkNonce := true
	fmt.Println("TeeComplianceStatus:", teeComplianceStatus)

	if !checkTee {
		fmt.Println("TeeComplianceStatus is not compliant-cvm")
	}
	if !checkPubkey {
		fmt.Println("Public Key does not match")
	}
	if !checkNonce {
		fmt.Println("Nonce does not match")
	}

	// 5. check user-data field (is the hash of the pubkey)
	// 5.1 read user-data measurement from jwtToken
	userData := ""
	userData, ok = token.Payload["x-ms-runtime"].(map[string]interface{})["user-data"].(string)
	if !ok {
		return true, true, true, false, fmt.Errorf("parsing x-ms-runtime.user-data in payload failed")
	}
	exptUserData = strings.ToUpper(exptUserData)
	fmt.Println("UserData measurement:", userData)
	fmt.Println("Expected UserData measurement:", exptUserData)
	checkUserData := exptUserData == userData
	return checkTee, checkPubkey, checkNonce, checkUserData, nil
}

/* validate MAA JWT  */
func ValidateJWTwithPSH(jwtToken string) (bool, error) {
	// 1. 保存当前工作目录
	currentDir, err := os.Getwd()
	fmt.Printf("currentDir:%s\n", currentDir)
	if err != nil {
		return false, fmt.Errorf("failed to get current working directory: %v", err)
	}

	// 2. 设置工作目录
	workDir := psh_script
	fmt.Printf("workDir:%s\n", workDir)
	if err := os.Chdir(workDir); err != nil {
		return false, fmt.Errorf("failed to change directory to %s: %v", workDir, err)
	}

	// 3. 启动 PowerShell 环境
	cmd := exec.Command("sudo", "pwsh")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("./Confirm-AttestationTokenSignature.ps1 -Jwt '%s'\n", jwtToken))
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	// 4. 执行命令并捕获输出
	fmt.Printf("Start PowerShell Script\n")
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("error running PowerShell command: %v\nstderr: %s", err, errOut.String())
	}

	// 5. 恢复原工作目录
	fmt.Printf("Restore to original working directory\n")
	if err := os.Chdir(currentDir); err != nil {
		return false, fmt.Errorf("failed to restore original working directory: %v", err)
	}

	// 6. 检查输出
	output := out.String()
	fmt.Println("PowerShell Output:", output)
	if strings.Contains(output, "Hash result: True") {
		return true, nil
	}

	return false, nil

}

func GetPeerTeeType(jwtToken string) (string, error) {
	// 1. 解析 JWT
	token, err := ParseJWT(jwtToken)
	if err != nil {
		return "", err
	}

	// 2. 读取 x-ms-isolation-tee.x-ms-compliance-status 字段
	teeType, ok := token.Payload["x-ms-attestation-type"].(string)
	if !ok {
		return "", errors.New("missing x-ms-attestation-type in payload")
	}

	if teeType != "tdxvm" { //SNP JWT Structure
		teeType, ok = token.Payload["x-ms-isolation-tee"].(map[string]interface{})["x-ms-attestation-type"].(string)
		if !ok {
			return "", errors.New("missing x-ms-isolation-tee.x-ms-attestation-type in payload")
		}
	}
	return teeType, nil
}

/* Calculate the expected value of the user_data */
func CalExptUserData(certPath string, hashFile string) string {
	pubkey := CallOpensslGetPubkey(certPath)
	pubkey = ExtractPubkeyFromPem(pubkey)
	fmt.Println("pubkey used in calExptUserData:", pubkey)

	//read the content from hashfile path
	hashValue, err := ioutil.ReadFile(hashFile)
	if err != nil {
		fmt.Println("Error reading hash file:", err)
		return ""
	}
	// hashValue = bytes.TrimSpace(hashValue)
	hashValueStr := strings.TrimSpace(string(hashValue))

	// Create JSON object
	userDataJSON := map[string]string{ //map是无序的;实际顺序是：prigramID->pubkey;已调整TPM注入脚本
		"pubkey":    pubkey,
		"programID": hashValueStr,
	}
	//Marshal the map into JSON bytes
	userDataJSONBytes, err := json.Marshal(userDataJSON)
	if err != nil {
		fmt.Println("Error marshalling user data JSON:", err)
		return ""
	}
	fmt.Println("UserData JSON:", string(userDataJSONBytes))
	//Calculate the SHA512 hash of the JSON string
	hash := sha512.Sum512(userDataJSONBytes)
	hashBytes := hash[:] //Convert [64] byte to []byte
	hashHex := fmt.Sprintf("%x", hashBytes)

	return hashHex
}
