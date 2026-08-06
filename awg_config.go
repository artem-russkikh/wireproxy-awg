package wireproxy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ini/ini"
)

// Header protection uses the S1-S4 crypto padding as the cipher nonce, so every
// padding has to be at least as large as that nonce.
// Mirrors device.HeaderCipherNonceSize of amneziawg-go.
const headerCipherNonceSize = 12

type ASecConfigType struct {
	junkPacketCount               int    // Jc
	junkPacketMinSize             int    // Jmin
	junkPacketMaxSize             int    // Jmax
	initPacketJunkSize            int    // s1
	responsePacketJunkSize        int    // s2
	cookieReplyPacketJunkSize     int    // s3
	transportPacketJunkSize       int    // s4
	initPacketMagicHeader         uint32 // h1
	initPacketMagicHeaderMax      uint32 // h1 upper bound
	responsePacketMagicHeader     uint32 // h2
	responsePacketMagicHeaderMax  uint32 // h2 upper bound
	underloadPacketMagicHeader    uint32 // h3
	underloadPacketMagicHeaderMax uint32 // h3 upper bound
	transportPacketMagicHeader    uint32 // h4
	transportPacketMagicHeaderMax uint32 // h4 upper bound
	hasJunkPacketCount            bool
	hasJunkPacketMinSize          bool
	hasJunkPacketMaxSize          bool
	hasInitPacketJunkSize         bool
	hasResponsePacketJunkSize     bool
	hasCookieReplyPacketJunkSize  bool
	hasTransportPacketJunkSize    bool
	hasInitPacketMagicHeader      bool
	hasResponsePacketMagicHeader  bool
	hasUnderloadPacketMagicHeader bool
	hasTransportPacketMagicHeader bool
	i1                            *string
	i2                            *string
	i3                            *string
	i4                            *string
	i5                            *string
	headerProtectionKey           *string    // HeaderProtectionKey, hex-encoded
	contentPaddingAddition        *uintRange // ContentPaddingAddition
	rekeyAfterTime                *uintRange // RekeyAfterTime, seconds
	rekeyTimeout                  *uintRange // RekeyTimeout, seconds
	rejectAfterTime               *uintRange // RejectAfterTime, seconds
	keepaliveTimeout              *uintRange // KeepaliveTimeout, seconds
	maxHandshakeAttempts          *uintRange // MaxHandshakeAttempts
}

// uintRange is an AmneziaWG interval parameter, written as either "a" or "a-b".
// The device picks a random value inside the interval for every packet it sends.
type uintRange struct {
	min uint32
	max uint32
}

func (r uintRange) String() string {
	if r.min == r.max {
		return strconv.FormatUint(uint64(r.min), 10)
	}
	return strconv.FormatUint(uint64(r.min), 10) + "-" + strconv.FormatUint(uint64(r.max), 10)
}

func ParseASecConfig(section *ini.Section) (*ASecConfigType, error) {
	var aSecConfig *ASecConfigType

	if sectionKey, err := section.GetKey("Jc"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.junkPacketCount = value
		aSecConfig.hasJunkPacketCount = true
	}

	if sectionKey, err := section.GetKey("Jmin"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.junkPacketMinSize = value
		aSecConfig.hasJunkPacketMinSize = true
	}

	if sectionKey, err := section.GetKey("Jmax"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.junkPacketMaxSize = value
		aSecConfig.hasJunkPacketMaxSize = true
	}

	if sectionKey, err := section.GetKey("S1"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.initPacketJunkSize = value
		aSecConfig.hasInitPacketJunkSize = true
	}

	if sectionKey, err := section.GetKey("S2"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.responsePacketJunkSize = value
		aSecConfig.hasResponsePacketJunkSize = true
	}

	if sectionKey, err := section.GetKey("S3"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.cookieReplyPacketJunkSize = value
		aSecConfig.hasCookieReplyPacketJunkSize = true
	}

	if sectionKey, err := section.GetKey("S4"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return nil, err
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.transportPacketJunkSize = value
		aSecConfig.hasTransportPacketJunkSize = true
	}

	if sectionKey, err := section.GetKey("H1"); err == nil {
		value, err := parseUintRange(sectionKey.String())
		if err != nil {
			return nil, fmt.Errorf("invalid H1 value: %w", err)
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.initPacketMagicHeader = value.min
		aSecConfig.initPacketMagicHeaderMax = value.max
		aSecConfig.hasInitPacketMagicHeader = true
	}

	if sectionKey, err := section.GetKey("H2"); err == nil {
		value, err := parseUintRange(sectionKey.String())
		if err != nil {
			return nil, fmt.Errorf("invalid H2 value: %w", err)
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.responsePacketMagicHeader = value.min
		aSecConfig.responsePacketMagicHeaderMax = value.max
		aSecConfig.hasResponsePacketMagicHeader = true
	}

	if sectionKey, err := section.GetKey("H3"); err == nil {
		value, err := parseUintRange(sectionKey.String())
		if err != nil {
			return nil, fmt.Errorf("invalid H3 value: %w", err)
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.underloadPacketMagicHeader = value.min
		aSecConfig.underloadPacketMagicHeaderMax = value.max
		aSecConfig.hasUnderloadPacketMagicHeader = true
	}

	if sectionKey, err := section.GetKey("H4"); err == nil {
		value, err := parseUintRange(sectionKey.String())
		if err != nil {
			return nil, fmt.Errorf("invalid H4 value: %w", err)
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.transportPacketMagicHeader = value.min
		aSecConfig.transportPacketMagicHeaderMax = value.max
		aSecConfig.hasTransportPacketMagicHeader = true
	}

	if sectionKey, err := section.GetKey("I1"); err == nil {
		value := sectionKey.String()
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.i1 = &value
	}

	if sectionKey, err := section.GetKey("I2"); err == nil {
		value := sectionKey.String()
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.i2 = &value
	}

	if sectionKey, err := section.GetKey("I3"); err == nil {
		value := sectionKey.String()
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.i3 = &value
	}

	if sectionKey, err := section.GetKey("I4"); err == nil {
		value := sectionKey.String()
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.i4 = &value
	}

	if sectionKey, err := section.GetKey("I5"); err == nil {
		value := sectionKey.String()
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.i5 = &value
	}

	if sectionKey, err := section.GetKey("HeaderProtectionKey"); err == nil {
		value, err := encodeBase64ToHex(sectionKey.String())
		if err != nil {
			return nil, fmt.Errorf("invalid HeaderProtectionKey value: %w", err)
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.headerProtectionKey = &value
	}

	rangeKeys := []struct {
		name string
		dst  func(*ASecConfigType) **uintRange
	}{
		{"ContentPaddingAddition", func(c *ASecConfigType) **uintRange { return &c.contentPaddingAddition }},
		{"RekeyAfterTime", func(c *ASecConfigType) **uintRange { return &c.rekeyAfterTime }},
		{"RekeyTimeout", func(c *ASecConfigType) **uintRange { return &c.rekeyTimeout }},
		{"RejectAfterTime", func(c *ASecConfigType) **uintRange { return &c.rejectAfterTime }},
		{"KeepaliveTimeout", func(c *ASecConfigType) **uintRange { return &c.keepaliveTimeout }},
		{"MaxHandshakeAttempts", func(c *ASecConfigType) **uintRange { return &c.maxHandshakeAttempts }},
	}

	for _, rangeKey := range rangeKeys {
		sectionKey, err := section.GetKey(rangeKey.name)
		if err != nil {
			continue
		}
		value, err := parseUintRange(sectionKey.String())
		if err != nil {
			return nil, fmt.Errorf("invalid %s value: %w", rangeKey.name, err)
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		*rangeKey.dst(aSecConfig) = &value
	}

	if err := ValidateASecConfig(aSecConfig); err != nil {
		return nil, err
	}

	return aSecConfig, nil
}

func ValidateASecConfig(config *ASecConfigType) error {
	if config == nil {
		return nil
	}
	if config.hasJunkPacketCount && (config.junkPacketCount < 1 || config.junkPacketCount > 128) {
		return errors.New("value of the Jc field must be within the range of 1 to 128")
	}
	if config.hasJunkPacketMinSize && config.hasJunkPacketMaxSize &&
		config.junkPacketMinSize > config.junkPacketMaxSize {
		return errors.New("value of the Jmin field must be less than or equal to Jmax field value")
	}
	if config.hasJunkPacketMaxSize && config.junkPacketMaxSize > 1280 {
		return errors.New("value of the Jmax field must be less than or equal 1280")
	}

	const messageInitiationSize = 148
	const messageResponseSize = 92
	const messageCookieReplySize = 64
	const messageTransportSize = 32

	type packetSizeCheck struct {
		isSet bool
		size  int
	}

	packetSizes := []packetSizeCheck{
		{isSet: config.hasInitPacketJunkSize, size: messageInitiationSize + config.initPacketJunkSize},
		{isSet: config.hasResponsePacketJunkSize, size: messageResponseSize + config.responsePacketJunkSize},
		{isSet: config.hasCookieReplyPacketJunkSize, size: messageCookieReplySize + config.cookieReplyPacketJunkSize},
		{isSet: config.hasTransportPacketJunkSize, size: messageTransportSize + config.transportPacketJunkSize},
	}
	for i := 0; i < len(packetSizes); i++ {
		if !packetSizes[i].isSet {
			continue
		}
		for j := i + 1; j < len(packetSizes); j++ {
			if !packetSizes[j].isSet {
				continue
			}
			if packetSizes[i].size == packetSizes[j].size {
				if config.hasCookieReplyPacketJunkSize || config.hasTransportPacketJunkSize {
					return errors.New(
						"value of the field S1 + message initiation size (148) must not equal S2 + message response size (92) + S3 + cookie reply size (64) + S4 + transport packet size (32)",
					)
				}
				return errors.New(
					"value of the field S1 + message initiation size (148) must not equal S2 + message response size (92)",
				)
			}
		}
	}

	intervals := collectEffectiveHeaderIntervals(config)
	for _, interval := range intervals {
		if interval.min > interval.max {
			return errors.New("invalid magic header range: lower bound cannot exceed upper bound")
		}
	}
	if hasOverlappingHeaderIntervals(intervals) {
		return errors.New("values of the H1-H4 fields must be unique")
	}

	if config.headerProtectionKey != nil {
		for _, padding := range []packetSizeCheck{
			{isSet: config.hasInitPacketJunkSize, size: config.initPacketJunkSize},
			{isSet: config.hasResponsePacketJunkSize, size: config.responsePacketJunkSize},
			{isSet: config.hasCookieReplyPacketJunkSize, size: config.cookieReplyPacketJunkSize},
			{isSet: config.hasTransportPacketJunkSize, size: config.transportPacketJunkSize},
		} {
			if !padding.isSet || padding.size < headerCipherNonceSize {
				return fmt.Errorf(
					"values of the S1-S4 fields must all be at least %d when HeaderProtectionKey is set",
					headerCipherNonceSize,
				)
			}
		}
	}

	return nil
}

type headerInterval struct {
	key string
	min uint32
	max uint32
}

const (
	defaultInitPacketMagicHeader      uint32 = 1
	defaultResponsePacketMagicHeader  uint32 = 2
	defaultUnderloadPacketMagicHeader uint32 = 3
	defaultTransportPacketMagicHeader uint32 = 4
)

func parseUintRange(value string) (uintRange, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return uintRange{}, errors.New("empty range value")
	}

	parts := strings.Split(trimmed, "-")
	if len(parts) == 0 || len(parts) > 2 || parts[0] == "" {
		return uintRange{}, errors.New("invalid range format")
	}

	minRaw, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return uintRange{}, err
	}
	minValue := uint32(minRaw)

	if len(parts) == 1 {
		return uintRange{min: minValue, max: minValue}, nil
	}
	if parts[1] == "" {
		return uintRange{}, errors.New("invalid range format")
	}

	maxRaw, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return uintRange{}, err
	}
	maxValue := uint32(maxRaw)
	if minValue > maxValue {
		return uintRange{}, errors.New("invalid range: lower bound cannot exceed upper bound")
	}

	return uintRange{min: minValue, max: maxValue}, nil
}

func collectEffectiveHeaderIntervals(config *ASecConfigType) []headerInterval {
	intervals := make([]headerInterval, 0, 4)

	h1Min, h1Max := defaultInitPacketMagicHeader, defaultInitPacketMagicHeader
	if config != nil && config.hasInitPacketMagicHeader {
		h1Min, h1Max = config.initPacketMagicHeader, config.initPacketMagicHeaderMax
	}
	intervals = append(intervals, headerInterval{key: "h1", min: h1Min, max: h1Max})

	h2Min, h2Max := defaultResponsePacketMagicHeader, defaultResponsePacketMagicHeader
	if config != nil && config.hasResponsePacketMagicHeader {
		h2Min, h2Max = config.responsePacketMagicHeader, config.responsePacketMagicHeaderMax
	}
	intervals = append(intervals, headerInterval{key: "h2", min: h2Min, max: h2Max})

	h3Min, h3Max := defaultUnderloadPacketMagicHeader, defaultUnderloadPacketMagicHeader
	if config != nil && config.hasUnderloadPacketMagicHeader {
		h3Min, h3Max = config.underloadPacketMagicHeader, config.underloadPacketMagicHeaderMax
	}
	intervals = append(intervals, headerInterval{key: "h3", min: h3Min, max: h3Max})

	h4Min, h4Max := defaultTransportPacketMagicHeader, defaultTransportPacketMagicHeader
	if config != nil && config.hasTransportPacketMagicHeader {
		h4Min, h4Max = config.transportPacketMagicHeader, config.transportPacketMagicHeaderMax
	}
	intervals = append(intervals, headerInterval{key: "h4", min: h4Min, max: h4Max})

	return intervals
}

func hasOverlappingHeaderIntervals(intervals []headerInterval) bool {
	for i := 0; i < len(intervals); i++ {
		for j := i + 1; j < len(intervals); j++ {
			left := intervals[i]
			right := intervals[j]
			if left.min <= right.max && right.min <= left.max {
				return true
			}
		}
	}
	return false
}

func formatMagicHeaderInterval(minValue uint32, maxValue uint32) string {
	return uintRange{min: minValue, max: maxValue}.String()
}
