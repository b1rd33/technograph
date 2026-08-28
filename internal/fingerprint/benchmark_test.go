package fingerprint

import (
	"testing"

	technograph "github.com/b1rd33/technograph"
	"github.com/b1rd33/technograph/internal/model"
)

func BenchmarkDefaultFingerprintDetect(b *testing.B) {
	database, _, err := Load(technograph.DefaultFingerprints(), true)
	if err != nil {
		b.Fatal(err)
	}
	engine := NewEngine(database)
	signals := []model.Signal{
		{Channel: model.ChannelHeader, Name: "cf-ray", Value: "abc"},
		{Channel: model.ChannelCookie, Name: "intercom-session", Value: "present"},
		{Channel: model.ChannelScript, Value: "https://js.stripe.com/v3/"},
		{Channel: model.ChannelScript, Value: "gtag('config', 'G-1')"},
		{Channel: model.ChannelHTML, Value: `<script src="https://cdn.shopify.com/app.js"></script>`},
		{Channel: model.ChannelDNSMX, Value: "aspmx.l.google.com"},
		{Channel: model.ChannelDNSTXT, Value: "include:sendgrid.net"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		technologies, evidence := engine.Detect(signals)
		if len(technologies) == 0 || len(evidence) == 0 {
			b.Fatal("expected detections")
		}
	}
}
