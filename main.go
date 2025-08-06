package main

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	xrate "golang.org/x/time/rate"

	"github.com/miekg/dns"
)

var (
	rateLimiters = make(map[string]*xrate.Limiter)
	mu           sync.Mutex

	GLOBAL_ZONENAME    = "errors.example.com"
	GLOBAL_NAMESERVERS = []string{"ns1.errors.example.com"}
	GLOBAL_TXTRESPONSE = "Thank you for your report"
)

// getLimiter returns a rate limiter for a given key, creating one if necessary.
func getLimiter(key string, maxEvents int, duration time.Duration) *xrate.Limiter {
	mu.Lock()
	defer mu.Unlock()
	if limiter, exists := rateLimiters[key]; exists {
		return limiter
	}
	limiter := xrate.NewLimiter(xrate.Every(duration/time.Duration(maxEvents)), maxEvents)
	rateLimiters[key] = limiter
	return limiter
}

// dnsHandler processes all incoming DNS requests.
func dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	remoteAddr, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		log.Printf("Failed to parse remote address: %v", err)
		return
	}

	// query rate limit based on remote address
	limiter := getLimiter("query-"+remoteAddr, 10, 20*time.Second)
	if !limiter.Allow() {
		log.Printf("Rate limit exceeded for %s", remoteAddr)
		sendBlockedResponse(w, r)
		return
	}

	// get question
	if len(r.Question) == 0 {
		log.Printf("Received empty question from %s", remoteAddr)
		sendNodataResponse(w, r)
		return
	}

	question := r.Question[0]
	log.Printf("Received question: %s %s from %s", dns.TypeToString[question.Qtype], question.Name, remoteAddr)

	// check if the qname ends with the global zone name
	if !strings.HasSuffix(strings.ToLower(question.Name), GLOBAL_ZONENAME+".") {
		log.Printf("Question %s does not match global zone name %s", question.Name, GLOBAL_ZONENAME)
		sendNotAuthResponse(w, r)
		return
	}

	if question.Qtype == dns.TypeNS {
		sendNSResponse(w, r)
		return
	}

	if question.Qtype == dns.TypeSOA {
		sendSOAResponse(w, r)
		return
	}

	if question.Qtype == dns.TypeTXT {
		handleReport(r)
		sendTXTResponse(w, r)
		return
	}

	sendNodataResponse(w, r)

}

func handleReport(m *dns.Msg) {
	// extract the qname, QTYPE, and EDE error code from the question
	qname, qtype, ede, err := extractrfc9567(m.Question[0].Name)
	if err != nil {
		log.Printf("Failed to extract RFC9567 information: %v", err)
		return
	}
	qtypename := dns.TypeToString[qtype]

	log.Printf("Received report for QNAME: %s, QTYPE: %d(%s), EDE CODE: %d", qname, qtype, qtypename, ede)

	additionalInfo := extractEDE(m)
	if additionalInfo != "" {
		log.Printf("Additional EDE information: %s", additionalInfo)
	}

}

func sendTXTResponse(w dns.ResponseWriter, r *dns.Msg) {

	qname := r.Question[0].Name

	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.SetRcode(r, dns.RcodeSuccess)

	// add TXT record
	txt := &dns.TXT{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Txt: []string{GLOBAL_TXTRESPONSE},
	}
	msg.Answer = append(msg.Answer, txt)

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("Failed to write TXT response: %v", err)
	}
}

func sendSOAResponse(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.SetRcode(r, dns.RcodeSuccess)

	// serial: current timestamp YYYYMMDD
	now := time.Now()
	serial := uint32(now.Year()*1000000 + int(now.Month())*10000 + now.Day()*100 + 1)

	// add SOA record
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   GLOBAL_ZONENAME + ".",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		Ns:      GLOBAL_NAMESERVERS[0] + ".",
		Mbox:    "hostmaster" + GLOBAL_ZONENAME + ".",
		Serial:  serial,
		Refresh: 3600,
		Retry:   1800,
		Expire:  604800,
		Minttl:  3600,
	}
	msg.Answer = append(msg.Answer, soa)
	if err := w.WriteMsg(msg); err != nil {
		log.Printf("Failed to write SOA response: %v", err)
	}
}

func sendNotAuthResponse(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.SetRcode(r, dns.RcodeNotAuth)

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("Failed to write NOTAUTH response: %v", err)
	}
}

func sendNSResponse(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.SetRcode(r, dns.RcodeSuccess)

	// add NS records
	for _, ns := range GLOBAL_NAMESERVERS {
		msg.Ns = append(msg.Ns, &dns.NS{
			Hdr: dns.RR_Header{
				Name:   GLOBAL_ZONENAME + ".",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns: ns + ".",
		})
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("Failed to write NS response: %v", err)
	}
}

func sendBlockedResponse(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.SetRcode(r, dns.RcodeRefused)

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("Failed to write REFUSED + BLOCKED EDE response: %v", err)
	}
}

func sendNotIMPResponse(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.SetRcode(r, dns.RcodeNotImplemented)

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("Failed to write NOTIMP response: %v", err)
	}
}

func sendNodataResponse(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.SetRcode(r, dns.RcodeSuccess)

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("Failed to write NODATA response: %v", err)
	}
}

func listen() {
	srv_cds := &dns.Server{
		Addr:    ":5300",
		Net:     "udp",
		Handler: dns.HandlerFunc(dnsHandler),
	}

	log.Printf("Starting Error Report listener on %s", srv_cds.Addr)
	if err := srv_cds.ListenAndServe(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func main() {

	// Start the DNS server
	go listen()

	// Block forever
	select {}
}

// extract RFC9567 information from the qname
// Returns the qname, QTYPE, and EDE error code if successful, or an error if the format is incorrect.
func extractrfc9567(qname string) (string, uint16, uint16, error) {
	/*
	   *  A label containing the string "_er".

	   *  The QTYPE that was used in the query that resulted in the extended
	      DNS error, presented as a decimal value, in a single DNS label.
	      If additional QTYPEs were present in the query, such as described
	      in [MULTI-QTYPES], they are represented as unique, ordered decimal
	      values separated by a hyphen.  As an example, if both QTYPE A and
	      AAAA were present in the query, they are presented as the label
	      "1-28".

	   *  The list of non-null labels representing the query name that is
	      the subject of the DNS error report.

	   *  The extended DNS error code, presented as a decimal value, in a
	      single DNS label.

	   *  A label containing the string "_er".
	*/

	// first, make sure the qname ends with the global zone name
	if !strings.HasSuffix(strings.ToLower(qname), GLOBAL_ZONENAME+".") {
		return "", 0, 0, fmt.Errorf("QNAME does not match global zone name: %s", qname)
	}
	// remove the global zone name from the qname
	qname = strings.TrimSuffix(strings.ToLower(qname), "."+GLOBAL_ZONENAME+".")

	// initialize a slice to hold the parts
	parts := strings.Split(qname, ".")

	// print parts
	log.Printf("Extracting parts from QNAME: %s", qname)

	// the first and the last parts should be "_er"
	if len(parts) < 3 || parts[0] != "_er" || parts[len(parts)-1] != "_er" {
		return "", 0, 0, fmt.Errorf("QNAME does not start and end with '_er': %s", qname)
	}

	// the second part should be the QTYPE (numeric)
	qtypeLabel := parts[1]
	qtypeno, err := strconv.ParseUint(qtypeLabel, 10, 16)
	if err != nil {
		return "", 0, 0, fmt.Errorf("invalid QTYPE label: %s", qtypeLabel)
	}
	qtype := uint16(qtypeno)
	// make sure qtypeno is valid
	if _, ok := dns.TypeToString[qtype]; !ok {
		return "", 0, 0, fmt.Errorf("QTYPE %d is not a valid DNS type", qtypeno)
	}

	// the second to last part should be the error code
	errorCodeLabel := parts[len(parts)-2]
	ede, converr := strconv.ParseUint(errorCodeLabel, 10, 16)
	if converr != nil {
		return "", 0, 0, fmt.Errorf("invalid error code label: %s", errorCodeLabel)
	}

	// extract the qname from the remaining parts
	qnameParts := parts[2 : len(parts)-2]
	// join the qname parts back together
	qname = strings.Join(qnameParts, ".")

	return qname, qtype, uint16(ede), nil
}

// extractEDE returns the RFC8914 error message if available
func extractEDE(message *dns.Msg) (ede_message string) {
	for _, k := range message.Extra {
		if opt, ok := k.(*dns.OPT); ok {
			for _, o := range opt.Option {
				switch o.(type) {
				case *dns.EDNS0_EDE:
					ede_message := o.String()
					return ede_message
				}
			}
		}
	}
	return ""
}
