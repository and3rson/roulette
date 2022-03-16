package modes

import (
	"fmt"
	"strings"
)

func CheckTelnet(addr string) (bool, []string, error) {
	conn, err := Connect(fmt.Sprintf("%s:%d", addr, 23))
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			return false, nil, fmt.Errorf("CheckTelnet: %s", err)
		} else {
			return false, nil, nil
		}
	}
	defer conn.Close()

	// conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	// return false, nil, nil
	return true, []string{"telnet"}, nil
}
