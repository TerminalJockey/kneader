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
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

var (
	domain   string
	wordlist string
	resolver string
	output   string
	timeout  int
	verbose  bool
)

func init() {
	flag.StringVar(&domain, "d", "", "domain to enumerate")
	flag.IntVar(&timeout, "t", 1, "request timeout")
	flag.StringVar(&wordlist, "w", "", "wordlist for bruteforce")
	flag.StringVar(&resolver, "r", "", "resolver to query")
	flag.StringVar(&output, "o", "", "output directory, defaults to no output")
	flag.BoolVar(&verbose, "v", false, "verbose output")
	flag.Parse()
}

func main() {
	if resolver == "" || wordlist == "" {
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

	scanner := bufio.NewScanner(wf)
	for scanner.Scan() {
		if verbose {
			scandom := fmt.Sprintf("%s.%s", scanner.Text(), domain)
			ret := NameToIPs(scandom)
			fmt.Println(scandom)
			fmt.Println(ret)
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
		} else {
			scandom := fmt.Sprintf("%s.%s", scanner.Text(), domain)
			ret := NameToIPs(scandom)
			if len(ret) > 0 {
				fmt.Printf("%s %s\n", scandom, ret)
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
		}
	}
	if outfileHandle != nil {
		outfileHandle.Close()
	}
}

func NameToIPs(name string) (ips []net.IP) {
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: false, Authoritative: true, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(fmt.Sprintf("%s.", name)), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
		Answers:   []dnsmessage.Resource{},
	}
	pmsg, err := msg.Pack()
	if err != nil {
		log.Println(err)
	}
	b64msg := make([]byte, base64.RawURLEncoding.EncodedLen(len(pmsg)))
	base64.RawURLEncoding.Encode(b64msg, pmsg)

	tr := http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	c := http.Client{Transport: &tr, Timeout: time.Second * time.Duration(timeout)}

	qstr := fmt.Sprintf("https://%s/dns-query?dns=%s", resolver, b64msg)
	req, err := http.NewRequest("GET", qstr, nil)
	if err != nil {
		log.Println(err)
	}
	req.Header.Add("accept", "application/dns-message")
	resp, err := c.Do(req)
	if err != nil {
		log.Println(err)
	}
	defer resp.Body.Close()
	rcon, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
	}
	if verbose {
		fmt.Println(rcon)
	}
	var p dnsmessage.Parser
	_, err = p.Start(rcon)
	if err != nil {
		log.Println(err)
	}
	p.SkipAllQuestions()
	var gotIPs []net.IP
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
