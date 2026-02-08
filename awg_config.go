package wireproxy

import (
	"errors"
	"strconv"
	"strings"

	"github.com/go-ini/ini"
)

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
		minValue, maxValue, err := parseMagicHeaderInterval(sectionKey.String())
		if err != nil {
			return nil, err
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.initPacketMagicHeader = minValue
		aSecConfig.initPacketMagicHeaderMax = maxValue
		aSecConfig.hasInitPacketMagicHeader = true
	}

	if sectionKey, err := section.GetKey("H2"); err == nil {
		minValue, maxValue, err := parseMagicHeaderInterval(sectionKey.String())
		if err != nil {
			return nil, err
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.responsePacketMagicHeader = minValue
		aSecConfig.responsePacketMagicHeaderMax = maxValue
		aSecConfig.hasResponsePacketMagicHeader = true
	}

	if sectionKey, err := section.GetKey("H3"); err == nil {
		minValue, maxValue, err := parseMagicHeaderInterval(sectionKey.String())
		if err != nil {
			return nil, err
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.underloadPacketMagicHeader = minValue
		aSecConfig.underloadPacketMagicHeaderMax = maxValue
		aSecConfig.hasUnderloadPacketMagicHeader = true
	}

	if sectionKey, err := section.GetKey("H4"); err == nil {
		minValue, maxValue, err := parseMagicHeaderInterval(sectionKey.String())
		if err != nil {
			return nil, err
		}
		if aSecConfig == nil {
			aSecConfig = &ASecConfigType{}
		}
		aSecConfig.transportPacketMagicHeader = minValue
		aSecConfig.transportPacketMagicHeaderMax = maxValue
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

func parseMagicHeaderInterval(value string) (uint32, uint32, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, 0, errors.New("empty magic header value")
	}

	parts := strings.Split(trimmed, "-")
	if len(parts) == 0 || len(parts) > 2 || parts[0] == "" {
		return 0, 0, errors.New("invalid magic header range format")
	}

	minRaw, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, err
	}
	minValue := uint32(minRaw)

	if len(parts) == 1 {
		return minValue, minValue, nil
	}
	if parts[1] == "" {
		return 0, 0, errors.New("invalid magic header range format")
	}

	maxRaw, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, err
	}
	maxValue := uint32(maxRaw)
	if minValue > maxValue {
		return 0, 0, errors.New("invalid magic header range: lower bound cannot exceed upper bound")
	}

	return minValue, maxValue, nil
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
	if minValue == maxValue {
		return strconv.FormatUint(uint64(minValue), 10)
	}
	return strconv.FormatUint(uint64(minValue), 10) + "-" + strconv.FormatUint(uint64(maxValue), 10)
}
