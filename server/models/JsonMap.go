package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// JSONMap is a map[string]interface{} that implements sql.Scanner and driver.Valuer
// for easy JSON storage in database columns
type JSONMap map[string]interface{}

// Value implements driver.Valuer for JSONMap
func (j JSONMap) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}

	// Handle empty map
	if len(j) == 0 {
		return "{}", nil
	}

	bytes, err := json.Marshal(j)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSONMap: %w", err)
	}
	return string(bytes), nil
}

// Scan implements sql.Scanner for JSONMap
func (j *JSONMap) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("JSONMap.Scan: unsupported type %T", value)
	}

	// Handle empty JSON
	if len(bytes) == 0 || string(bytes) == "null" {
		*j = JSONMap{}
		return nil
	}

	var result map[string]interface{}
	if err := json.Unmarshal(bytes, &result); err != nil {
		return fmt.Errorf("failed to unmarshal JSONMap: %w", err)
	}

	*j = result
	return nil
}

// MarshalJSON implements json.Marshaler for JSONMap
func (j JSONMap) MarshalJSON() ([]byte, error) {
	if j == nil {
		return []byte("null"), nil
	}
	return json.Marshal(map[string]interface{}(j))
}

// UnmarshalJSON implements json.Unmarshaler for JSONMap
func (j *JSONMap) UnmarshalJSON(data []byte) error {
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	*j = result
	return nil
}

// GetString returns a string value from the JSONMap
func (j JSONMap) GetString(key string) (string, bool) {
	if j == nil {
		return "", false
	}
	val, exists := j[key]
	if !exists {
		return "", false
	}
	str, ok := val.(string)
	return str, ok
}

// GetInt returns an int value from the JSONMap
func (j JSONMap) GetInt(key string) (int, bool) {
	if j == nil {
		return 0, false
	}
	val, exists := j[key]
	if !exists {
		return 0, false
	}

	// Handle both float64 (from JSON) and int
	switch v := val.(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	case int64:
		return int(v), true
	default:
		return 0, false
	}
}

// GetBool returns a bool value from the JSONMap
func (j JSONMap) GetBool(key string) (bool, bool) {
	if j == nil {
		return false, false
	}
	val, exists := j[key]
	if !exists {
		return false, false
	}
	b, ok := val.(bool)
	return b, ok
}

// GetMap returns a nested map from the JSONMap
func (j JSONMap) GetMap(key string) (JSONMap, bool) {
	if j == nil {
		return nil, false
	}
	val, exists := j[key]
	if !exists {
		return nil, false
	}

	if nestedMap, ok := val.(map[string]interface{}); ok {
		return JSONMap(nestedMap), true
	}
	return nil, false
}

// GetSlice returns a slice from the JSONMap
func (j JSONMap) GetSlice(key string) ([]interface{}, bool) {
	if j == nil {
		return nil, false
	}
	val, exists := j[key]
	if !exists {
		return nil, false
	}

	slice, ok := val.([]interface{})
	return slice, ok
}

// Set sets a value in the JSONMap
func (j JSONMap) Set(key string, value interface{}) {
	if j == nil {
		j = make(JSONMap)
	}
	j[key] = value
}

// Merge merges another map into the JSONMap
func (j JSONMap) Merge(other map[string]interface{}) {
	if j == nil {
		j = make(JSONMap)
	}
	for key, value := range other {
		j[key] = value
	}
}

// Clone creates a deep copy of the JSONMap
func (j JSONMap) Clone() JSONMap {
	if j == nil {
		return nil
	}

	clone := make(JSONMap)
	for key, value := range j {
		clone[key] = value
	}
	return clone
}

// String returns the JSON representation as a string
func (j JSONMap) String() string {
	if j == nil {
		return "null"
	}
	bytes, err := json.Marshal(j)
	if err != nil {
		return "{}"
	}
	return string(bytes)
}

// IsEmpty returns true if the map is nil or empty
func (j JSONMap) IsEmpty() bool {
	return j == nil || len(j) == 0
}
