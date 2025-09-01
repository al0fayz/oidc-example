package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
)

// StringArray is a []string that implements sql.Scanner and driver.Valuer
// for easy string array storage in database JSON columns
type StringArray []string

// Value implements driver.Valuer for StringArray
func (s StringArray) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}

	// Handle empty array
	if len(s) == 0 {
		return "[]", nil
	}

	bytes, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal StringArray: %w", err)
	}
	return string(bytes), nil
}

// Scan implements sql.Scanner for StringArray
func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}

	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("StringArray.Scan: unsupported type %T", value)
	}

	// Handle empty JSON
	if len(bytes) == 0 || string(bytes) == "null" {
		*s = StringArray{}
		return nil
	}

	var result []string
	if err := json.Unmarshal(bytes, &result); err != nil {
		return fmt.Errorf("failed to unmarshal StringArray: %w", err)
	}

	*s = result
	return nil
}

// Contains checks if the array contains a specific string
func (s StringArray) Contains(str string) bool {
	for _, item := range s {
		if item == str {
			return true
		}
	}
	return false
}

// Join returns a string representation joined by separator
func (s StringArray) Join(separator string) string {
	return strings.Join(s, separator)
}

// Append appends items to the array
func (s *StringArray) Append(items ...string) {
	*s = append(*s, items...)
}

// Remove removes all occurrences of an item from the array
func (s *StringArray) Remove(item string) {
	result := make(StringArray, 0, len(*s))
	for _, str := range *s {
		if str != item {
			result = append(result, str)
		}
	}
	*s = result
}

// Unique returns a new array with duplicate values removed
func (s StringArray) Unique() StringArray {
	seen := make(map[string]bool)
	result := make(StringArray, 0, len(s))

	for _, item := range s {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

// IsEmpty returns true if the array is nil or empty
func (s StringArray) IsEmpty() bool {
	return s == nil || len(s) == 0
}
