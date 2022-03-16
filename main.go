package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/and3rson/roulette/modes"
	"github.com/schollz/progressbar/v3"
	log "github.com/sirupsen/logrus"
)

var args struct {
	Filename string `arg:"positional,required" help:"CIDR file"`
	Output string `arg:"-o" help:"Output file for hits"`
	Concurrency int `arg:"-c" default:"4" help:"Maximum number of parallel requests"`
	StartFrom int `arg:"-i" help:"CIDR index to start with (1 is first)" default:"1"`
	Mode string `arg:"-m" help:"Mode (vnc, telnet, rtsp)"`
	Count int `arg:"-n" help:"How many CIDRs to scan, zero for no limit" default:"0"`
}

type Result struct {
	Addr string
	Hits []string
	Err error
}

func Checker(id string, ctx context.Context, wg *sync.WaitGroup, checkerFunc CheckerFunc, addrs <-chan string, results chan<- Result) {
	// log.Infof("checker %s: started", id)
	defer func() {
		wg.Done()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case addr, ok := <-addrs:
			if !ok {
				return
			}
			isExploitable, hits, err := checkerFunc(addr)
			if err != nil {
				results <- Result{Addr: addr, Hits: nil, Err: fmt.Errorf("checker %s: %s", id, err)}
				continue
			}
			if isExploitable {
				results <- Result{Addr: addr, Hits: hits, Err: nil}
			} else {
				results <- Result{Addr: addr, Hits: nil, Err: nil}
			}
		}
	}
}

func ProcessCidrBlock(ctx context.Context, checkerFunc CheckerFunc, cidrBlock string) (<-chan Result, int) {
	results := make(chan Result, 1024)
	host := net.ParseIP(cidrBlock)
	var hosts []string
	if host == nil {
		hosts = Hosts(cidrBlock)
	} else {
		hosts = []string{host.String()}
	}
	go func() {
		wg := &sync.WaitGroup{}
		addrs := make(chan string, 0)
		for i := 0; i < args.Concurrency; i++ {
			wg.Add(1)
			go Checker(fmt.Sprint(i), ctx, wg, checkerFunc, addrs, results)
		}
		defer func(){
			close(addrs)
			wg.Wait()
			close(results)
		}()
		for _, host := range hosts {
			select {
			case addrs <- host:
				// fmt.Printf("try %s\n", host)
			case <-ctx.Done():
				return
			}
		}
	}()
	return results, len(hosts)
}

func main() {
	arg.MustParse(&args)
	log.SetLevel(log.DebugLevel)
	// log.SetLevel(log.InfoLevel)
	// log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		DisableLevelTruncation: true,
		DisableColors: false,
	})
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	file, err := os.Open(args.Filename)
	if err != nil {
		log.Fatal(err)
	}
	cidrBlocks := []string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		cidrBlocks = append(cidrBlocks, scanner.Text())
	}
	log.Infof("loaded %d CIDR blocks", len(cidrBlocks))
	ctx, cancel := context.WithCancel(context.Background())
	var checkerFunc CheckerFunc
	switch args.Mode {
	case "vnc":
		checkerFunc = modes.CheckVNC
		break
	case "telnet":
		checkerFunc = modes.CheckTelnet
		break
	case "rtsp":
		checkerFunc = modes.CheckRTSP
		break
	case "":
		log.Fatalf("Mode must be provided")
	default:
		log.Fatalf("Unknown mode: %s", args.Mode)
	}
	// defer cancel()
	func() {
		// counter := 0
		i := 0
		for i < args.Count || args.Count == 0 {
			cidrIndex := args.StartFrom + i - 1
			if cidrIndex >= len(cidrBlocks) {
				return
			}
			cidrBlock := cidrBlocks[cidrIndex]
			// log.Infof("CIDR block %d started", cidrIndex + 1)
			results, total := ProcessCidrBlock(ctx, checkerFunc, cidrBlock)
			finished := false
			bar := progressbar.Default(int64(total))
			<-time.After(time.Second / 10)
			bar.RenderBlank()
			for !finished {
				select {
				case result, ok := <-results:
					if !ok {
						log.Infof("CIDR block %d finished", cidrIndex + 1)
						finished = true
					} else {
						bar.Describe(fmt.Sprintf("CIDR %d/%d: %-15s", cidrIndex + 1, len(cidrBlocks), result.Addr))
						bar.Add(1)
						if result.Err != nil {
							fmt.Println()
							log.Errorf("%s: %v", result.Addr, result.Err)
						}
						if len(result.Hits) > 0 {
							log.WithField("addr", result.Addr).Infof("%s: hit: %s", result.Addr, result.Hits)
							if args.Output != "" {
								outFile, err := os.OpenFile(args.Output, os.O_CREATE | os.O_APPEND | os.O_WRONLY, 0644)
								if err != nil {
									log.Fatal("Failed to open output file:", err)
								}
								outFile.WriteString(result.Addr + " " + strings.Join(result.Hits, " ") + "\n")
								outFile.Close()
							}
						}
					}
				case <-c:
					log.Warn("received interrupt signal, stopping")
					cancel()
					for range results {}
					return
				}
			}
			// log.Infof("entering new CIDR block: %d/%d, (%d hosts)", cidrIndex + 1, len(cidrBlocks), len(hosts))
			// bar := progressbar.Default(int64(len(hosts)))
			// bar.Describe(fmt.Sprintf("CIDR %d/%d (%d hosts)", cidrIndex + 1, len(cidrBlocks), len(hosts)))
			i++
		}
	}()
	// close(addrs)
	// wg.Wait()
}
