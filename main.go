package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"golang.org/x/net/dns/dnsmessage"
)

var (
	domain   string
	wordlist string
	resolver string
	output   string
	ports    string
	Ports    []string
	verbose  bool
	vhosts   bool
	timeout  int
	threads  int

	mutex = sync.RWMutex{}
)

type Host struct {
	Address string
	Domains []Domain
}

type Domain struct {
	Name        string
	Fingerprint []string
}

func init() {
	flag.StringVar(&domain, "d", "", "domain to enumerate")
	flag.StringVar(&wordlist, "w", "", "wordlist for bruteforce")
	flag.StringVar(&resolver, "r", "", "resolver to query")
	flag.StringVar(&output, "o", "", "output directory, defaults to no output")
	flag.StringVar(&ports, "p", "", "ports to scan")
	flag.BoolVar(&vhosts, "vhosts", false, "bruteforce subdomains/vhosts on found ips")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.IntVar(&timeout, "to", 1, "request timeout")
	flag.IntVar(&threads, "t", 1, "threads")
	flag.Parse()

	Ports = strings.Split(ports, ",")
}

func main() {
	if resolver == "" || wordlist == "" || output == "" || ports == "" {
		log.Println("check flags and rerun")
		os.Exit(0)
	}
	wf, err := os.Open(wordlist)
	if err != nil {
		log.Println(err)
	}
	defer wf.Close()

	var outfileHandle *os.File = nil

	if output != "" {
		outfile := fmt.Sprintf("%s/%s.%d.log", output, domain, time.Now().UnixNano())
		outfileHandle, err = os.Create(outfile)
		if err != nil {
			log.Println(err)
		}
	}

	// initial dns enumeration to gather subdomains and ips
	var wg sync.WaitGroup
	throttle := make(chan int, threads)
	tr := http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	c := http.Client{Transport: &tr, Timeout: time.Second * time.Duration(timeout)}

	scanner := bufio.NewScanner(wf)
	for scanner.Scan() {
		throttle <- 1
		wg.Add(1)
		go func(scannerText string, wg *sync.WaitGroup, throttle chan int) {
			defer wg.Done()
			scandom := fmt.Sprintf("%s.%s", scannerText, domain)
			ret := NameToIPs(scandom, c)
			if verbose {
				fmt.Printf("%s %s\n", scandom, ret)
			}
			mutex.Lock()
			if len(ret) > 0 {
				if outfileHandle != nil {
					outfileHandle.WriteString(scandom + "|")
					for x := range ret {
						outfileHandle.WriteString(ret[x].String())
						if x != len(ret)-1 {
							outfileHandle.WriteString(",")
						}
					}
					outfileHandle.WriteString("\n")
				}
			}
			mutex.Unlock()
			<-throttle
		}(scanner.Text(), &wg, throttle)
	}
	wg.Wait()

	outfileHandle.Seek(0, 0)

	// vhost grind found ips
	if vhosts {
		var iplist []string
		scanner = bufio.NewScanner(outfileHandle)
		for scanner.Scan() {
			ips := strings.Split(strings.Split(scanner.Text(), "|")[1], ",")
			fmt.Println(ips)
			for x := range ips {
				var contains bool
				for y := range iplist {
					if ips[x] == iplist[y] {
						contains = true
					}
				}
				if !contains {
					iplist = append(iplist, ips[x])
				}
			}
		}
		fmt.Println(iplist)

		for x := range iplist {
			wf.Seek(0, 0)
			wfscanner := bufio.NewScanner(wf)
			for wfscanner.Scan() {
				throttle <- 1
				wg.Add(1)
				go func(scannerText string, wg *sync.WaitGroup, throttle chan int) {
					defer wg.Done()
					fulldomain := fmt.Sprintf("%s.%s", scannerText, domain)
					newreq, err := http.NewRequest("GET", fmt.Sprintf("http://%s", iplist[x]), nil)
					if err != nil {
						log.Println(err)
						<-throttle
						return
						// continue
					}

					newreq.Host = fulldomain
					resp, err := c.Do(newreq)
					if err != nil {
						// log.Println(err)
						<-throttle
						return
						// continue
					}
					defer resp.Body.Close()
					if resp.StatusCode != 403 {
						mutex.Lock()
						fmt.Println(fulldomain)
						fmt.Println(resp.Status, resp.ContentLength)
						mutex.Unlock()
					}
					<-throttle
				}(wfscanner.Text(), &wg, throttle)
			}
			wg.Wait()
		}
	}
	outfileHandle.Seek(0, 0)

	// port scan of found ips
	scanner = bufio.NewScanner(outfileHandle)
	for scanner.Scan() {
		FingerprintDomain(scanner.Text(), c)
	}

	if outfileHandle != nil {
		outfileHandle.Close()
	}
}

func FingerprintDomain(line string, c http.Client) {
	s := strings.Split(line, "|")
	domain := s[0]
	wapClient, err := wappalyzer.New()
	if err != nil {
		log.Println(err)
	}
	for x := range Ports {
		var resp *http.Response
		var url string
		url = fmt.Sprintf("http://%s:%s", domain, Ports[x])
		resp, err = c.Get(url)
		if err != nil {
			continue
		}
		if resp.StatusCode == 400 {
			url = fmt.Sprintf("https://%s:%s", domain, Ports[x])
			resp, err = c.Get(url)
		}
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Println(err)
		}

		fingerprints, title := wapClient.FingerprintWithTitle(resp.Header, data)
		if title == "" {
			fmt.Println(strings.TrimSpace(url))
		} else {
			fmt.Println(strings.TrimSpace(url), strings.TrimSpace(title))
		}

		for a, _ := range fingerprints {
			fmt.Printf("%s\n", a)
		}
	}
}

func IPToNames(ip string, c http.Client) (names []string) {
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: false, Authoritative: true, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(fmt.Sprintf("%s.in-addr.arpa.", ip)), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}},
		Answers:   []dnsmessage.Resource{},
	}
	pmsg, err := msg.Pack()
	if err != nil {
		log.Println(err)
		return names
	}
	b64msg := make([]byte, base64.RawURLEncoding.EncodedLen(len(pmsg)))
	base64.RawURLEncoding.Encode(b64msg, pmsg)
	qstr := fmt.Sprintf("https://%s/dns-query?dns=%s", resolver, b64msg)
	req, err := http.NewRequest("GET", qstr, nil)
	if err != nil {
		log.Println(err)
		return names
	}
	req.Header.Add("accept", "application/dns-message")
	resp, err := c.Do(req)
	if err != nil {
		log.Println("doreq", err)
		if err.Error() == "connectex: Only one usage of each socket address (protocol/network address/port) is normally permitted." {
			time.Sleep(500 * time.Millisecond)
			return IPToNames(ip, c)
		}
		return names
	}
	defer resp.Body.Close()
	rcon, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return names
	}
	if verbose {
		fmt.Println(rcon)
	}
	var p dnsmessage.Parser
	_, err = p.Start(rcon)
	if err != nil {
		log.Println(err)
		return names
	}
	p.SkipAllQuestions()

	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			panic(err)
		}
		switch h.Type {
		case dnsmessage.TypePTR:
			r, err := p.PTRResource()
			if err != nil {
				panic(err)
			}
			names = append(names, r.PTR.String())

		default:
			p.SkipAnswer()
		}
	}
	return names
}

func NameToIPs(name string, c http.Client) (ips []net.IP) {
	if len(name) > 255 {
		return ips
	}
	var gotIPs []net.IP
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: false, Authoritative: true, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(fmt.Sprintf("%s.", name)), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers:   []dnsmessage.Resource{},
	}
	pmsg, err := msg.Pack()
	if err != nil {
		log.Println(err)
		return gotIPs
	}
	b64msg := make([]byte, base64.RawURLEncoding.EncodedLen(len(pmsg)))
	base64.RawURLEncoding.Encode(b64msg, pmsg)
	qstr := fmt.Sprintf("https://%s/dns-query?dns=%s", resolver, b64msg)
	req, err := http.NewRequest("GET", qstr, nil)
	if err != nil {
		log.Println(err)
		return gotIPs
	}
	req.Header.Add("accept", "application/dns-message")
	resp, err := c.Do(req)
	if err != nil {
		log.Println("doreq", err)
		if err.Error() == "connectex: Only one usage of each socket address (protocol/network address/port) is normally permitted." {
			time.Sleep(500 * time.Millisecond)
			return NameToIPs(name, c)
		}
		return gotIPs
	}
	defer resp.Body.Close()
	rcon, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return gotIPs
	}
	if verbose {
		fmt.Println(rcon)
	}
	var p dnsmessage.Parser
	_, err = p.Start(rcon)
	if err != nil {
		log.Println(err)
		return gotIPs
	}
	p.SkipAllQuestions()

	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			panic(err)
		}
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				panic(err)
			}
			gotIPs = append(gotIPs, r.A[:])
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				panic(err)
			}
			gotIPs = append(gotIPs, r.AAAA[:])
		default:
			p.SkipAnswer()
		}
	}
	return gotIPs
}
