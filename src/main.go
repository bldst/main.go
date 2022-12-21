package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql" // init
	"github.com/jmoiron/sqlx"          //sql x
	"log"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 21计本专1 曹稳龙 5122512021071
type User struct {
	Id       int    //id
	Account  string //账号
	Psd      string //密码
	Secret   string //二步验证密钥
	Authcode int    //二步验证码

}
type Reply struct {
	statuscode int         `json:"code"` // 作为状态标识  200 成功，300 失败 ，310 输入有误 ，320 输出有误
	Msg        string      `json:"msg"`  // 给用户提示的
	Data       interface{} `json:"data"` //返回数据/返回开发者查看的错误信息 void* object 可以存放任意数据类型
}

// 注册
func register(w http.ResponseWriter, r *http.Request) {
	user := User{}
	Mod := Reply{}
	//处理跨域问题
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	//设置返回为json格式
	w.Header().Set("content-type", "text/json")

	r.ParseForm() //接收get post 等请求
	account := r.Form.Get("account")
	psd := r.Form.Get("psd")
	log.Println("name.psd===> ", account, psd)

	//生成二步验证密钥
	fmt.Println("----------------- 生成secret -------------------")
	secret := GetSecret()
	fmt.Println("secret:" + secret)

	dsn := "cwl:cwlsld@tcp(175.178.192.115:3306)/go?charset=utf8mb4&parseTime=True"
	db, err := sqlx.Open("mysql", dsn)
	log.Print(db, err)
	//注册插入数据库
	_, err = db.Exec("insert into user(account, psd, secret)values(?, ?, ?)", account, psd, secret)
	if err != nil { //没有数据或有多条数据则失败
		fmt.Printf("get failed, err:%v\n", err)
		Mod.statuscode = 204
		Mod.Msg = "注册失败"
		jsonbytes, _ := json.Marshal(Mod)

		w.Write(jsonbytes)
		return
	}

	user.Psd = psd
	user.Secret = secret
	user.Account = account
	//返回成功状态
	Mod.Data = user
	Mod.statuscode = 200
	Mod.Msg = "注册成功"
	log.Print("注册成功")
	jsonbytes, _ := json.Marshal(Mod)
	w.Write(jsonbytes)
	db.Close()
}

// 登陆功能
func login(w http.ResponseWriter, r *http.Request) {
	user := User{}
	Mod := Reply{}
	//处理跨域问题
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
	//设置返回为json格式
	w.Header().Set("content-type", "text/json")

	r.ParseForm() //接收get post 等请求
	account := r.Form.Get("account")
	psd := r.Form.Get("psd")
	authcode, _ := strconv.ParseInt(r.Form.Get("authcode"), 10, 32)
	log.Println("name.psd===> ", account, psd, authcode)

	dsn := "cwl:cwlsld@tcp(175.178.192.115:3306)/go?charset=utf8mb4&parseTime=True"
	db, err := sqlx.Open("mysql", dsn)
	log.Print(db, err)
	//查询账户密码是否匹配
	err = db.Get(&user, "select * from user where account=? and psd=?", account, psd)
	if err != nil { //没有数据或有多条数据则失败
		fmt.Printf("get failed, err:%v\n", err)
		Mod.statuscode = 204
		Mod.Msg = "账号密码错误"
		jsonbytes, _ := json.Marshal(Mod)

		w.Write(jsonbytes)
		return
	}
	//从数据返回存在密钥，说明开启了二步验证，需要进行 二步验证操作
	if len(user.Secret) > 0 {
		log.Print(user.Secret, user.Authcode)
		b := VerifyCode(user.Secret, int32(authcode))
		if b {
			fmt.Println("验证成功！")
			Mod.Data = user
			Mod.statuscode = 200
			Mod.Msg = "登陆成功"
			log.Print("登陆成功登陆id为：", user.Id)
			jsonbytes, _ := json.Marshal(Mod)
			w.Write(jsonbytes)
		} else {
			Mod.statuscode = 204
			Mod.Msg = "二步验证失败"
			jsonbytes, _ := json.Marshal(Mod)

			w.Write(jsonbytes)
			fmt.Println("验证失败！")
		}

	} else {
		//没有开启二步验证直接 封装返回
		Mod.Data = user
		Mod.statuscode = 200
		Mod.Msg = "登陆成功"
		log.Print("登陆成功登陆id为：", user.Id)
		jsonbytes, _ := json.Marshal(Mod)
		w.Write(jsonbytes)
	}

	db.Close()
}

func main() {
	http.HandleFunc("/register", register)
	http.HandleFunc("/login", login)
	http.ListenAndServe(":8089", nil)

}
func GetSecret() string {
	randomStr := randStr(16)
	return strings.ToUpper(randomStr)
}

func randStr(strSize int) string {
	dictionary := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var bytes = make([]byte, strSize)
	_, _ = rand.Read(bytes)
	for k, v := range bytes {
		bytes[k] = dictionary[v%byte(len(dictionary))]
	}
	return string(bytes)
}

// 为了考虑时间误差，判断前当前时间及前后30秒时间
func VerifyCode(secret string, code int32) bool {
	// 当前google值
	if getCode(secret, 0) == code {
		return true
	}

	// 前30秒google值
	if getCode(secret, -30) == code {
		return true
	}

	// 后30秒google值
	if getCode(secret, 30) == code {
		return true
	}

	return false
}

// 获取Google Code
func getCode(secret string, offset int64) int32 {
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		fmt.Println(err)
		return 0
	}

	//使用时间间隔为 30 秒的时间生成一次性密码
	epochSeconds := time.Now().Unix() + offset
	return int32(oneTimePassword(key, toBytes(epochSeconds/30)))
}

func toBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	shifts := [8]uint16{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func toUint32(bytes []byte) uint32 {
	return (uint32(bytes[0]) << 24) + (uint32(bytes[1]) << 16) +
		(uint32(bytes[2]) << 8) + uint32(bytes[3])
}

func oneTimePassword(key []byte, value []byte) uint32 {
	// sign the value using HMAC-SHA1
	hmacSha1 := hmac.New(sha1.New, key)
	hmacSha1.Write(value)
	hash := hmacSha1.Sum(nil)

	// We're going to use a subset of the generated hash.
	// Using the last nibble (half-byte) to choose the index to start from.
	// This number is always appropriate as it's maximum decimal 15, the hash will
	// have the maximum index 19 (20 bytes of SHA1) and we need 4 bytes.
	offset := hash[len(hash)-1] & 0x0F

	// get a 32-bit (4-byte) chunk from the hash starting at offset
	hashParts := hash[offset : offset+4]

	// ignore the most significant bit as per RFC 4226
	hashParts[0] = hashParts[0] & 0x7F

	number := toUint32(hashParts)

	// size to 6 digits
	// one million is the first number with 7 digits so the remainder
	// of the division will always return < 7 digits
	pwd := number % 1000000

	return pwd
}
