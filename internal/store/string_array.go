package store

import (
	"database/sql/driver"
	"fmt"
	"strings"
)

type StringArray []string

func (s StringArray) Value() (driver.Value, error) {
	if s == nil {
		return "", nil
	}

	return strings.Join(s, ";"), nil
}

func (s *StringArray) Scan(value interface{}) error {
	// case when value from the db was NULL
	if value == nil {
		return nil
	}

	st, ok := value.(string)
	if !ok {
		return fmt.Errorf("failed to cast value to string: %v", value)
	}

	*s = strings.Split(st, ";")

	return nil
}
