// Copyright Ricardo Oliveira 2025.
// SPDX-License-Identifier: MPL-2.0

package openaisecrets

import (
	"encoding/json"
	"fmt"
	"time"
)

// UnixTime wraps time.Time for custom UnmarshalJSON implementation
// to handle Unix timestamp formats from the OpenAI API
type UnixTime time.Time

// UnmarshalJSON implements custom unmarshaling for Unix timestamps
// It handles timestamps in seconds (integer), RFC3339 format (string), or null
func (ut *UnixTime) UnmarshalJSON(data []byte) error {
	// Handle null or empty values
	if string(data) == "null" || string(data) == `""` || len(data) == 0 {
		*ut = UnixTime(time.Time{})
		return nil
	}

	// Try parsing as RFC3339 string first
	var timeStr string
	if err := json.Unmarshal(data, &timeStr); err == nil {
		t, err := time.Parse(time.RFC3339, timeStr)
		if err == nil {
			*ut = UnixTime(t)
			return nil
		}
	}

	// Try parsing as Unix timestamp (seconds since epoch)
	var unixTime int64
	if err := json.Unmarshal(data, &unixTime); err == nil {
		// If this is a very large number, assume it's milliseconds
		if unixTime > 1000000000000 {
			// Correct millisecond handling: ms -> sec, nsec
			sec := unixTime / 1000
			nsec := (unixTime % 1000) * 1e6
			*ut = UnixTime(time.Unix(sec, nsec))
		} else {
			*ut = UnixTime(time.Unix(unixTime, 0))
		}
		return nil
	}

	// Try parsing as float for fractional seconds
	var floatTime float64
	if err := json.Unmarshal(data, &floatTime); err == nil {
		sec := int64(floatTime)
		nsec := int64((floatTime - float64(sec)) * 1e9)
		*ut = UnixTime(time.Unix(sec, nsec))
		return nil
	}

	// If all parsing attempts failed, return an error
	return fmt.Errorf("cannot unmarshal timestamp: %s", string(data))
}

// MarshalJSON converts the UnixTime back to JSON
func (ut UnixTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(ut).Format(time.RFC3339))
}

// Time returns the time.Time value
func (ut UnixTime) Time() time.Time {
	return time.Time(ut)
}

// TimePtr returns a pointer to a time.Time value
func (ut UnixTime) TimePtr() *time.Time {
	t := time.Time(ut)
	return &t
}

// UnixTimePtr converts a time.Time pointer to a UnixTime pointer
func UnixTimePtr(t *time.Time) *UnixTime {
	if t == nil {
		return nil
	}
	ut := UnixTime(*t)
	return &ut
}
