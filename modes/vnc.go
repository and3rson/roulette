package modes

import (
	"bufio"
	"crypto/des"
	"fmt"
	"math/bits"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
)

func Min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func Connect(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, 2 * time.Second + time.Millisecond * time.Duration(rand.Intn(1000)))
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func HelloVNC(conn net.Conn) ([]int, error) {
	n := 0
	var err error
	buf := make([]byte, 128)
	n, err = conn.Read(buf[:])
	if err != nil {
		return nil, err
	}
	if string(buf[:3]) != "RFB" {
		return nil, fmt.Errorf("unexpected response: %v", buf[:n])
	}
	_, err = conn.Write(buf[:12])
	if err != nil {
		return nil, err
	}
	n, err = conn.Read(buf[:])
	if err != nil {
		return nil, err
	}
	result := []int{}
	for i := 1; i < Min(n, int(buf[0] + 1)); i++ {
		result = append(result, int(buf[i]))
	}
	return result, nil
}

func TryPasswordVNC(conn net.Conn, password string) (bool, error) {
	buf := make([]byte, 128)
	if _, err := conn.Write([]byte{2}); err != nil {
		return false, err
	}
	n, err := conn.Read(buf[:])
	if err != nil {
		return false, err
	}
	challenge := buf[:16]
	key := make([]byte, 8)
	for i := 0; i < Min(8, len(password)); i++ {
		key[i] = bits.Reverse8(password[i])
	}
	cipher, err := des.NewCipher(key)
	if err != nil {
		return false, err
	}
	ciphered := make([]byte, 16)
	cipher.Encrypt(ciphered, challenge[:8])
	cipher.Encrypt(ciphered[8:], challenge[8:])
	if _, err := conn.Write(ciphered); err != nil {
		return false, err
	}
	_, err = conn.Read(buf[:])
	if err != nil {
		return false, err
	}
	if n > 4 && buf[3] == 0 {
		return true, nil
	} else {
		return false, nil
	}
}

func CheckVNC(addr string) (bool, []string, error) {
	addr = fmt.Sprintf("%s:%d", addr, 5900)
	conn, err := Connect(addr)
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			return false, nil, fmt.Errorf("CheckVNC: %s", err)
		} else {
			return false, nil, nil
		}
	}

	conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	defer conn.Close()
	methods, err := HelloVNC(conn)
	if err != nil {
		return false, nil, err
	}
	// fmt.Println("a" + string(buf[:n]) + "b", buf[:n])
	// fmt.Println(string(buf[:n]) == "Authentication failed")
	// if string(buf[:n]) == "Authentication failed" {
	// 	return false, nil
	// }
	hasAuth := false
	for _, method := range methods {
		if method == 1 {
			return true, []string{"vnc"}, nil
		} else if method == 2 {
			hasAuth = true
		}
	}

	// fmt.Println("Bruteforce", methods)
	if hasAuth {
		passwordsFile, err := os.Open("passwords.dat")
		if err != nil {
			return false, nil, fmt.Errorf("open passwords file: %s", err)
		}
		scanner := bufio.NewScanner(passwordsFile)
		conn.Close()
		for scanner.Scan() {
			password := scanner.Text()
			// fmt.Println("Try", password)
			conn, err = net.DialTimeout("tcp", addr, time.Second * 5)
			if err != nil {
				continue
				// return false, "", fmt.Errorf("reconnect to host for bruteforce: %s", err)
			}
			conn.SetReadDeadline(time.Now().Add(time.Second * 5))
			if _, err := HelloVNC(conn); err != nil {
				// fmt.Println(err)
				continue
				// return false, "", err
			}
			ok, err := TryPasswordVNC(conn, password)
			if err != nil {
				continue
				// return false, "", err
			}
			if ok {
				return true, []string{"vnc", password}, nil
			}
		}
	}
	return false, nil, nil
}
