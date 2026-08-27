package probe

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/b1rd33/technograph/internal/model"
	"github.com/miekg/dns"
)

func TestDNSProbeCollectsAndNormalizesRecords(t *testing.T) {
	t.Parallel()
	exchanger := exchangeFunc(func(_ context.Context, message *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(message)
		switch message.Question[0].Qtype {
		case dns.TypeMX:
			response.Answer = []dns.RR{
				&dns.MX{Hdr: rrHeader("example.com.", dns.TypeMX), Preference: 10, Mx: "ASPMX.L.GOOGLE.COM."},
			}
		case dns.TypeTXT:
			response.Answer = []dns.RR{
				&dns.TXT{Hdr: rrHeader("example.com.", dns.TypeTXT), Txt: []string{"include:", "sendgrid.net"}},
				&dns.TXT{Hdr: rrHeader("example.com.", dns.TypeTXT), Txt: []string{"second"}},
			}
		case dns.TypeCNAME:
			response.Answer = []dns.RR{
				&dns.CNAME{Hdr: rrHeader("example.com.", dns.TypeCNAME), Target: "Site.Salesforce.com."},
			}
		}
		return response, 0, nil
	})
	probe, err := NewDNSProbe(DNSOptions{Servers: []string{"resolver:53"}, Timeout: time.Second, UDP: exchanger, TCP: exchanger})
	if err != nil {
		t.Fatalf("NewDNSProbe: %v", err)
	}
	result, signals := probe.Probe(context.Background(), "Example.COM")
	if strings.Join(result.MX, "|") != "aspmx.l.google.com" {
		t.Fatalf("MX = %v", result.MX)
	}
	if strings.Join(result.TXT, "|") != "include:sendgrid.net|second" {
		t.Fatalf("TXT = %v", result.TXT)
	}
	if strings.Join(result.CNAME, "|") != "site.salesforce.com" {
		t.Fatalf("CNAME = %v", result.CNAME)
	}
	if len(signals) != 4 {
		t.Fatalf("signal count = %d, want 4", len(signals))
	}
	assertDNSChannel(t, signals, model.ChannelDNSMX)
	assertDNSChannel(t, signals, model.ChannelDNSTXT)
	assertDNSChannel(t, signals, model.ChannelDNSCNAME)
}

func TestDNSProbeRetriesTruncatedUDPOverTCP(t *testing.T) {
	t.Parallel()
	var mutex sync.Mutex
	tcpCalls := 0
	udp := exchangeFunc(func(_ context.Context, message *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(message)
		response.Truncated = true
		return response, 0, nil
	})
	tcp := exchangeFunc(func(_ context.Context, message *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		mutex.Lock()
		tcpCalls++
		mutex.Unlock()
		response := new(dns.Msg)
		response.SetReply(message)
		return response, 0, nil
	})
	probe, _ := NewDNSProbe(DNSOptions{Servers: []string{"resolver:53"}, Timeout: time.Second, UDP: udp, TCP: tcp})
	probe.Probe(context.Background(), "example.com")
	if tcpCalls != 3 {
		t.Fatalf("TCP calls = %d, want 3", tcpCalls)
	}
}

func TestDNSFailureIsIsolatedByRecordType(t *testing.T) {
	t.Parallel()
	exchanger := exchangeFunc(func(_ context.Context, message *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		if message.Question[0].Qtype == dns.TypeTXT {
			return nil, 0, errors.New("TXT blocked")
		}
		response := new(dns.Msg)
		response.SetReply(message)
		if message.Question[0].Qtype == dns.TypeMX {
			response.Answer = []dns.RR{&dns.MX{Hdr: rrHeader("example.com.", dns.TypeMX), Mx: "mail.example.com."}}
		}
		return response, 0, nil
	})
	probe, _ := NewDNSProbe(DNSOptions{Servers: []string{"resolver:53"}, Timeout: time.Millisecond, UDP: exchanger, TCP: exchanger})
	result, _ := probe.Probe(context.Background(), "example.com")
	if result.Errors["txt"] == "" || len(result.MX) != 1 || result.Status["cname"] != "nodata" {
		t.Fatalf("result = %#v", result)
	}
}

func TestDNSNXDomainIsNotAProbeError(t *testing.T) {
	t.Parallel()
	exchanger := exchangeFunc(func(_ context.Context, message *dns.Msg, _ string) (*dns.Msg, time.Duration, error) {
		response := new(dns.Msg)
		response.SetReply(message)
		response.Rcode = dns.RcodeNameError
		return response, 0, nil
	})
	probe, _ := NewDNSProbe(DNSOptions{Servers: []string{"resolver:53"}, Timeout: time.Second, UDP: exchanger, TCP: exchanger})
	result, _ := probe.Probe(context.Background(), "missing.example")
	if len(result.Errors) != 0 || result.Status["mx"] != "nxdomain" {
		t.Fatalf("result = %#v", result)
	}
}

func assertDNSChannel(t *testing.T, signals []model.Signal, channel model.Channel) {
	t.Helper()
	for _, signal := range signals {
		if signal.Channel == channel {
			return
		}
	}
	t.Fatalf("channel %s not found in %#v", channel, signals)
}

func rrHeader(name string, recordType uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: recordType, Class: dns.ClassINET, Ttl: 300}
}

type exchangeFunc func(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)

func (function exchangeFunc) ExchangeContext(ctx context.Context, message *dns.Msg, server string) (*dns.Msg, time.Duration, error) {
	return function(ctx, message, server)
}
