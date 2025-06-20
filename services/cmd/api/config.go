// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Service represents a single service with a name and port.
type Service struct {
	Name string
	Port int
}

// Config holds all configuration values for the application.
type Config struct {
	TickLength int
	StartDate  string
	MongoHost  string
	FlagRegex  string
	TrafficDir string
	VMIP       string
	Services   []Service
}

// ParseServices parses a space-separated list of service:port pairs.
func ParseServices(s string) ([]Service, error) {
	var services []Service
	s = strings.TrimSpace(s)
	if s == "" {
		return services, nil
	}

	parts := strings.FieldsSeq(s)
	for part := range parts {
		split := strings.Split(part, ":")
		if len(split) != 2 {
			return nil, fmt.Errorf("invalid service definition: %s", part)
		}

		name := split[0]
		port, err := strconv.Atoi(split[1])
		if err != nil {
			return nil, fmt.Errorf("invalid port for service %s: %v", part, err)
		} else if port <= 0 || port > 65535 {
			return nil, fmt.Errorf("port out of range for service %s: %d", part, port)
		}

		services = append(services, Service{Name: name, Port: port})
	}

	return services, nil
}

// LoadConfig reads configuration from environment variables.
func LoadConfig() (*Config, error) {
	getenv := func(key string, required bool) (string, error) {
		val := os.Getenv(key)
		if required && val == "" {
			return "", fmt.Errorf("missing required environment variable: %s", key)
		}
		return val, nil
	}

	tickLengthStr, err := getenv("TICK_LENGTH", true)
	if err != nil {
		return nil, err
	}
	tickLength, err := strconv.Atoi(tickLengthStr)
	if err != nil {
		return nil, fmt.Errorf("invalid TICK_LENGTH: %v", err)
	}

	startDate, err := getenv("TICK_START", true)
	if err != nil {
		return nil, err
	}
	mongoHost, err := getenv("TULIP_MONGO", true)
	if err != nil {
		return nil, err
	}
	flagRegex, err := getenv("FLAG_REGEX", true)
	if err != nil {
		return nil, err
	}
	trafficDir, err := getenv("TULIP_TRAFFIC_DIR", true)
	if err != nil {
		return nil, err
	}
	trafficDir, err = validateDirectory(trafficDir)
	if err != nil {
		return nil, err
	}
	vmIP, err := getenv("VM_IP", true)
	if err != nil {
		return nil, err
	}
	servicesStr, err := getenv("GAME_SERVICES", true)
	if err != nil {
		return nil, err
	}
	services, err := ParseServices(servicesStr)
	if err != nil {
		return nil, err
	}

	return &Config{
		TickLength: tickLength,
		StartDate:  startDate,
		MongoHost:  mongoHost,
		FlagRegex:  flagRegex,
		TrafficDir: trafficDir,
		VMIP:       vmIP,
		Services:   services,
	}, nil
}

// MongoServer returns the MongoDB connection string.
func (c *Config) MongoServer() string {
	return fmt.Sprintf("mongodb://%s/", c.MongoHost)
}

// validateDirectory checks if the given path exists and is a directory.
func validateDirectory(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("could not resolve path: %v", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("path does not exist: %s", abs)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("path is not a directory: %s", abs)
	}
	return abs, nil
}
