package assetmonitor

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

var protocolPattern = regexp.MustCompile(`^[a-z][a-z0-9+.-]{0,31}$`)

// NormalizeRootDomain accepts a registrable DNS root, converts IDNs to their
// ASCII form, and rejects public suffixes, IP literals, wildcards and
// subdomains. Monitoring a narrower hostname should be expressed by filtering
// a root-domain monitor rather than weakening the import boundary.
func NormalizeRootDomain(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if strings.HasPrefix(value, "*.") {
		return "", validationErrorf("root_domain must not contain a wildcard")
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil || !validDNSName(ascii) || net.ParseIP(ascii) != nil {
		return "", validationErrorf("root_domain is not a valid DNS name")
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil || !strings.EqualFold(registrable, ascii) {
		return "", validationErrorf("root_domain must be a registrable root domain")
	}
	return strings.ToLower(ascii), nil
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func normalizeCandidateDomain(value string) string {
	value = strings.TrimSpace(strings.Trim(value, `[]"'`))
	if strings.HasPrefix(value, "*.") {
		return ""
	}
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if value == "" || strings.ContainsAny(value, ",; 	\r\n") {
		return ""
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Scheme != "" {
		if parsed.User != nil {
			return ""
		}
		value = parsed.Hostname()
	} else if host, _, err := net.SplitHostPort(value); err == nil {
		value = strings.Trim(host, "[]")
	}
	if net.ParseIP(strings.Trim(value, "[]")) != nil {
		return ""
	}
	ascii, err := idna.Lookup.ToASCII(strings.TrimSuffix(value, "."))
	if err != nil || !validDNSName(strings.ToLower(ascii)) {
		return ""
	}
	return strings.ToLower(ascii)
}

func withinRoot(domain, root string) bool {
	return domain == root || strings.HasSuffix(domain, "."+root)
}

// NormalizeObservationForRoot is the final trust boundary before persistence.
// It requires a DNS name that proves exact-root or label-boundary subdomain
// membership. An IP-only result is therefore never importable.
func NormalizeObservationForRoot(root string, observation Observation) (Observation, bool) {
	normalizedRoot, err := NormalizeRootDomain(root)
	if err != nil {
		return Observation{}, false
	}
	domain := normalizeCandidateDomain(observation.Domain)
	if domain == "" {
		domain = normalizeCandidateDomain(observation.Host)
	}
	if domain == "" || !withinRoot(domain, normalizedRoot) {
		return Observation{}, false
	}

	observation.Domain = domain
	observation.Host = domain
	observation.IP = strings.ToLower(strings.Trim(strings.TrimSpace(observation.IP), "[]"))
	if observation.IP != "" && net.ParseIP(observation.IP) == nil {
		observation.IP = ""
	}
	if observation.Port < 0 || observation.Port > 65535 {
		return Observation{}, false
	}
	observation.Protocol = strings.ToLower(strings.TrimSpace(observation.Protocol))
	if observation.Protocol != "" && !protocolPattern.MatchString(observation.Protocol) {
		observation.Protocol = ""
	}
	if observation.Protocol == "" {
		switch observation.Port {
		case 80:
			observation.Protocol = "http"
		case 443:
			observation.Protocol = "https"
		}
	}
	observation.Title = cleanProviderText(observation.Title, 500)
	observation.Server = cleanProviderText(observation.Server, 255)
	observation.Country = cleanProviderText(observation.Country, 255)
	observation.Province = cleanProviderText(observation.Province, 255)
	observation.City = cleanProviderText(observation.City, 255)
	return observation, true
}

func cleanProviderText(value string, maxRunes int) string {
	value = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value))
	if utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	return strings.TrimSpace(string(runes[:maxRunes]))
}

func observationDedupKey(observation Observation) string {
	return strings.Join([]string{observation.Domain, strconv.Itoa(observation.Port), observation.Protocol}, "|")
}

func generatedQuery(root string) string { return `domain:"` + root + `"` }
