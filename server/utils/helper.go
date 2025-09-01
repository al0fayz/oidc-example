package utils

import "encoding/json"

// Helper function to handle JSON marshaling for MySQL
func MarshalJSON(data interface{}) (string, error) {
	if data == nil {
		return "NULL", nil
	}
	bytes, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Helper function to handle string arrays for MySQL
func MarshalStringArray(arr []string) (string, error) {
	if arr == nil {
		return "NULL", nil
	}
	bytes, err := json.Marshal(arr)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
