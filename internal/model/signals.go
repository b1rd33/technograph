package model

import "fmt"

// Channel identifies where a signal was observed.
type Channel string

const (
	ChannelHeader   Channel = "header"
	ChannelScript   Channel = "script"
	ChannelCookie   Channel = "cookie"
	ChannelHTML     Channel = "html"
	ChannelMeta     Channel = "meta"
	ChannelJS       Channel = "js"
	ChannelDNSTXT   Channel = "dns_txt"
	ChannelDNSCNAME Channel = "dns_cname"
	ChannelDNSMX    Channel = "dns_mx"
)

var supportedChannels = map[Channel]struct{}{
	ChannelHeader: {}, ChannelScript: {}, ChannelCookie: {}, ChannelHTML: {},
	ChannelMeta: {}, ChannelJS: {}, ChannelDNSTXT: {}, ChannelDNSCNAME: {},
	ChannelDNSMX: {},
}

// ParseChannel validates a serialized channel name.
func ParseChannel(value string) (Channel, error) {
	channel := Channel(value)
	if _, ok := supportedChannels[channel]; !ok {
		return "", fmt.Errorf("unsupported channel %q", value)
	}
	return channel, nil
}

// Part selects which structural component of a signal is matched.
type Part string

const (
	PartName  Part = "name"
	PartValue Part = "value"
)

// Signal is one normalized public observation.
type Signal struct {
	Channel Channel
	Name    string
	Value   string
	Origin  string
}

// Text returns the structural part selected by target.
func (signal Signal) Text(target Part) string {
	if target == PartName {
		return signal.Name
	}
	return signal.Value
}

// Evidence records why one fingerprint matched.
type Evidence struct {
	Technology string  `json:"technology"`
	Channel    Channel `json:"channel"`
	Selector   string  `json:"selector,omitempty"`
	Pattern    string  `json:"pattern"`
	Matched    string  `json:"matched"`
	Origin     string  `json:"origin"`
	Confidence int     `json:"confidence"`
}
