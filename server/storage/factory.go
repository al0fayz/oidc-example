package storage

import (
	"errors"
	"fmt"
)

type StorageType string

const (
	StorageTypeMySQL  StorageType = "mysql"
	StorageTypeMemory StorageType = "memory"
)

type Config struct {
	Type             StorageType
	ConnectionString string
	MaxOpenConns     int
	MaxIdleConns     int
}

func NewStorage(config Config) (Storage, error) {
	switch config.Type {
	case StorageTypeMySQL:
		if config.ConnectionString == "" {
			return nil, errors.New("connection string is required for MySQL storage")
		}
		return newMySQLStorage(config.ConnectionString)
	case StorageTypeMemory:
		return NewMemoryStorage()
	default:
		return nil, fmt.Errorf("unknown storage type: %s", config.Type)
	}
}

// DefaultConfig returns a default configuration for development
func DefaultConfig() Config {
	return Config{
		Type:             StorageTypeMemory, // Default to memory for development
		ConnectionString: "",
		MaxOpenConns:     25,
		MaxIdleConns:     5,
	}
}

// MySQLConfig returns a configuration for MySQL
func MySQLConfig(connectionString string) Config {
	return Config{
		Type:             StorageTypeMySQL,
		ConnectionString: connectionString,
		MaxOpenConns:     25,
		MaxIdleConns:     5,
	}
}

// MemoryConfig returns a configuration for in-memory storage
func MemoryConfig() Config {
	return Config{
		Type:             StorageTypeMemory,
		ConnectionString: "",
		MaxOpenConns:     0, // Not used for memory
		MaxIdleConns:     0, // Not used for memory
	}
}
