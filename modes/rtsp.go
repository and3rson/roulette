package modes

import (
	"fmt"
	"strings"

	"github.com/aler9/gortsplib"
	"github.com/aler9/gortsplib/pkg/base"
	"github.com/aler9/gortsplib/pkg/liberrors"
)

func CheckRTSP(addr string) (bool, []string, error) {
	conn, err := Connect(fmt.Sprintf("%s:%d", addr, 554))
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			return false, nil, fmt.Errorf("CheckTelnet: %s", err)
		} else {
			return false, nil, nil
		}
	}
	conn.Close()

	u, err := base.ParseURL(fmt.Sprintf("rtsp://%s", addr))
	client := gortsplib.Client{}
	if err := client.Start(u.Scheme, u.Host); err != nil {
		return false, nil, err
	}
	if _, _, _, err = client.Describe(u); err != nil {
		if _, ok := err.(liberrors.ErrClientBadStatusCode); ok {
			return false, nil, nil
		}
		return false, nil, err
	}
	return true, []string{"rtsp"}, nil

	// buffer := make([]byte, 4096)

	// conn.SetReadDeadline(time.Now().Add(time.Second * 5))
	// if _, err := conn.Write([]byte("OPTIONS /media.mp4 RTSP/1.0\nCSeq: 1\n\n")); err != nil {
	// 	return false, nil, err
	// }
	// // if _, err := conn.Read(buffer); err != nil {
	// // 	return false, nil, err
	// // }
	// reader := bufio.NewReader(conn)
	// resp, err := http.ReadResponse(reader, nil)
	// fmt.Println("Response:", resp, err)
	// // return false, nil, nil
}
