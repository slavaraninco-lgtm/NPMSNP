package config

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	BindHost                 string
	ExternalHost             string
	NSPort                   int
	SBPort                   int
	HTTPPort                 int
	DBPath                   string
	DBSecretKey              string
	AdminPassword            string
	ProjectName              string
	ServerName               string
	ServerVersion            string
	DefaultDomain            string
	ServiceAccountEmail      string
	ServiceAccountName       string
	AutoRegisterUnknownUsers bool
	AutoAddServiceContact    bool
	BypassPassportForTWN     bool
	SessionTimeout           time.Duration
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		return strings.TrimSpace(val)
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		if i, err := strconv.Atoi(strings.TrimSpace(val)); err == nil {
			return i
		}
	}
	return fallback
}

func getEnvBool(key string, fallback bool) bool {
	if val, ok := os.LookupEnv(key); ok && strings.TrimSpace(val) != "" {
		v := strings.ToLower(strings.TrimSpace(val))
		return v == "1" || v == "true" || v == "yes"
	}
	return fallback
}

// DetectDefaultExternalHost determines outward IP of the machine via UDP routing table lookup.
func DetectDefaultExternalHost() string {
	if envHost := os.Getenv("MSNP_EXTERNAL_HOST"); strings.TrimSpace(envHost) != "" {
		return strings.TrimSpace(envHost)
	}
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 500*time.Millisecond)
	if err == nil {
		defer conn.Close()
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		ip := localAddr.IP.String()
		if ip != "" && !strings.HasPrefix(ip, "127.") {
			return ip
		}
	}
	return "127.0.0.1"
}

// Load loads configuration from environment variables with sensible defaults.
func Load() *Config {
	baseDir, _ := os.Getwd()
	defaultDBPath := filepath.Join(baseDir, "database.db")

	return &Config{
		BindHost:                 getEnv("MSNP_BIND_HOST", "0.0.0.0"),
		ExternalHost:             DetectDefaultExternalHost(),
		NSPort:                   getEnvInt("MSNP_NS_PORT", 1863),
		SBPort:                   getEnvInt("MSNP_SB_PORT", 1864),
		HTTPPort:                 getEnvInt("MSNP_HTTP_PORT", 1865),
		DBPath:                   getEnv("MSNP_DB_PATH", defaultDBPath),
		DBSecretKey:              getEnv("MSNP_DB_SECRET_KEY", "msnp_server_default_master_salt_key_2026"),
		AdminPassword:            getEnv("MSNP_ADMIN_PASSWORD", "enc:v1:gAAAAABqrGOFz73J-WDRDYZdK2mk8lVVVicqvqxuIceBUQK-_J_kfnmUtnWN3fdrSS8cXj5gopHxwW8V6Bi2dupcwhkW2ibZew=="),
		ProjectName:              getEnv("MSNP_PROJECT_NAME", "NPMSNP"),
		ServerName:               getEnv("MSNP_SERVER_NAME", "NPMSNP Server"),
		ServerVersion:            "1.0.0",
		DefaultDomain:            "msn.local",
		ServiceAccountEmail:      "system@msn.local",
		ServiceAccountName:       "Служба сообщений MSN",
		AutoRegisterUnknownUsers: getEnvBool("MSNP_AUTO_REGISTER", true),
		AutoAddServiceContact:    getEnvBool("MSNP_AUTO_ADD_SERVICE", true),
		BypassPassportForTWN:     getEnvBool("MSNP_BYPASS_PASSPORT", true),
		SessionTimeout:           time.Duration(getEnvInt("MSNP_SESSION_TIMEOUT", 300)) * time.Second,
	}
}
