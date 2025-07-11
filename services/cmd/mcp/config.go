// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"
)

type Config struct {
	MongoHost string
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

	mongoHost, err := getenv("MONGO_HOST", true)
	if err != nil {
		return nil, err
	}

	return &Config{
		MongoHost: mongoHost,
	}, nil
}

// MongoServer returns the MongoDB connection string.
func (c *Config) MongoServer() string {
	return fmt.Sprintf("mongodb://%s/", c.MongoHost)
}
