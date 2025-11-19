package waf

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

type WAF struct {
	enabled bool
	rules   []Rule
}

type Rule struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	Action      Action
	Severity    Severity
	TargetField TargetField
}

type Action string

const (
	Block    Action = "block"
	Log      Action = "log"
	Challenge Action = "challenge"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
)

type TargetField string

const (
	URI        TargetField = "uri"
	QueryString TargetField = "query"
	Headers    TargetField = "headers"
	Body       TargetField = "body"
	UserAgent  TargetField = "user_agent"
)

func New(enabled bool) *WAF {
	waf := &WAF{
		enabled: enabled,
		rules:   make([]Rule, 0),
	}

	if enabled {
		waf.loadDefaultRules()
	}

	log.Info().Bool("enabled", enabled).Int("rules", len(waf.rules)).Msg("WAF initialized")

	return waf
}

func (w *WAF) loadDefaultRules() {
	// SQL Injection detection
	w.rules = append(w.rules, Rule{
		ID:          "SQLI-001",
		Name:        "SQL Injection Detection",
		Pattern:     regexp.MustCompile(`(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table|update.*set|exec.*xp_|'.*or.*'.*=.*')`),
		Action:      Block,
		Severity:    Critical,
		TargetField: QueryString,
	})

	// XSS detection
	w.rules = append(w.rules, Rule{
		ID:          "XSS-001",
		Name:        "Cross-Site Scripting Detection",
		Pattern:     regexp.MustCompile(`(?i)(<script|javascript:|onerror=|onload=|<iframe|eval\(|alert\()`),
		Action:      Block,
		Severity:    High,
		TargetField: QueryString,
	})

	// Path traversal
	w.rules = append(w.rules, Rule{
		ID:          "PATH-001",
		Name:        "Path Traversal Detection",
		Pattern:     regexp.MustCompile(`(\.\.\/|\.\.\\|etc\/passwd|windows\/system)`),
		Action:      Block,
		Severity:    High,
		TargetField: URI,
	})

	// Command injection
	w.rules = append(w.rules, Rule{
		ID:          "CMD-001",
		Name:        "Command Injection Detection",
		Pattern:     regexp.MustCompile(`(?i)(\||;|&&|\$\(|`+"`"+`|\n|>|<)`),
		Action:      Block,
		Severity:    Critical,
		TargetField: QueryString,
	})

	// XXE detection
	w.rules = append(w.rules, Rule{
		ID:          "XXE-001",
		Name:        "XML External Entity Detection",
		Pattern:     regexp.MustCompile(`(?i)(<!DOCTYPE|<!ENTITY|SYSTEM|PUBLIC)`),
		Action:      Block,
		Severity:    High,
		TargetField: Body,
	})

	// Common exploit patterns
	w.rules = append(w.rules, Rule{
		ID:          "EXP-001",
		Name:        "Common Exploit Patterns",
		Pattern:     regexp.MustCompile(`(?i)(phpinfo|shell_exec|system\(|passthru|eval\(|base64_decode)`),
		Action:      Block,
		Severity:    Critical,
		TargetField: QueryString,
	})

	// Suspicious user agents
	w.rules = append(w.rules, Rule{
		ID:          "UA-001",
		Name:        "Suspicious User Agent",
		Pattern:     regexp.MustCompile(`(?i)(sqlmap|nikto|nmap|masscan|nessus|burp|metasploit|havij|acunetix)`),
		Action:      Block,
		Severity:    Medium,
		TargetField: UserAgent,
	})

	// SSRF attempts
	w.rules = append(w.rules, Rule{
		ID:          "SSRF-001",
		Name:        "Server-Side Request Forgery",
		Pattern:     regexp.MustCompile(`(?i)(localhost|127\.0\.0\.1|169\.254\.|192\.168\.|10\.|172\.16\.)`),
		Action:      Log,
		Severity:    High,
		TargetField: QueryString,
	})

	// LFI detection
	w.rules = append(w.rules, Rule{
		ID:          "LFI-001",
		Name:        "Local File Inclusion",
		Pattern:     regexp.MustCompile(`(?i)(file:\/\/|php:\/\/|data:\/\/|expect:\/\/|zip:\/\/)`),
		Action:      Block,
		Severity:    High,
		TargetField: QueryString,
	})
}

func (w *WAF) CheckRequest(r *http.Request) (bool, *Rule) {
	if !w.enabled {
		return true, nil
	}

	// Extract fields to check
	fields := map[TargetField]string{
		URI:         r.URL.Path,
		QueryString: r.URL.RawQuery,
		UserAgent:   r.UserAgent(),
		Headers:     w.headersToString(r.Header),
	}

	// Check each rule
	for _, rule := range w.rules {
		if value, exists := fields[rule.TargetField]; exists {
			if rule.Pattern.MatchString(value) {
				log.Warn().
					Str("rule_id", rule.ID).
					Str("rule_name", rule.Name).
					Str("severity", string(rule.Severity)).
					Str("action", string(rule.Action)).
					Str("matched_value", value).
					Str("ip", w.getClientIP(r)).
					Msg("WAF rule triggered")

				if rule.Action == Block {
					return false, &rule
				}
			}
		}
	}

	return true, nil
}

func (w *WAF) headersToString(headers http.Header) string {
	var sb strings.Builder
	for key, values := range headers {
		for _, value := range values {
			sb.WriteString(key)
			sb.WriteString(": ")
			sb.WriteString(value)
			sb.WriteString("; ")
		}
	}
	return sb.String()
}

func (w *WAF) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := strings.Split(r.RemoteAddr, ":")[0]
	return ip
}

func (w *WAF) AddRule(rule Rule) {
	w.rules = append(w.rules, rule)
	log.Info().Str("rule_id", rule.ID).Str("rule_name", rule.Name).Msg("Added WAF rule")
}

func (w *WAF) RemoveRule(id string) {
	for i, rule := range w.rules {
		if rule.ID == id {
			w.rules = append(w.rules[:i], w.rules[i+1:]...)
			log.Info().Str("rule_id", id).Msg("Removed WAF rule")
			return
		}
	}
}

func (w *WAF) GetRules() []Rule {
	return w.rules
}

func (w *WAF) Enable() {
	w.enabled = true
	log.Info().Msg("WAF enabled")
}

func (w *WAF) Disable() {
	w.enabled = false
	log.Info().Msg("WAF disabled")
}
