package storage

import (
	"encoding/json"
	"oidc-example/server/models"
)

// Helper functions for JSONMap and StringArray handling in MySQL

func ScanJSONMap(data interface{}) (models.JSONMap, error) {
	if data == nil {
		return models.JSONMap{}, nil
	}

	var bytes []byte
	switch v := data.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return nil, nil
	}

	if len(bytes) == 0 {
		return models.JSONMap{}, nil
	}

	var result models.JSONMap
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func ScanStringArray(data interface{}) (models.StringArray, error) {
	if data == nil {
		return models.StringArray{}, nil
	}

	var bytes []byte
	switch v := data.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return nil, nil
	}

	if len(bytes) == 0 {
		return models.StringArray{}, nil
	}

	var result models.StringArray
	if err := json.Unmarshal(bytes, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// Value helpers for database operations
func ValueJSONMap(jm models.JSONMap) (interface{}, error) {
	if jm == nil {
		return nil, nil
	}
	return jm.Value()
}

func ValueStringArray(sa models.StringArray) (interface{}, error) {
	if sa == nil {
		return nil, nil
	}
	return sa.Value()
}
