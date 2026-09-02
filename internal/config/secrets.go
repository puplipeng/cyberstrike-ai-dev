package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// SecretMask is an editing sentinel, never a credential sent to a provider.
// Missing fields and this sentinel preserve the saved secret; an explicit
// empty string clears it. Responses contain only the sentinel or an empty value.
const SecretMask = "********"

func RedactedCopy[T any](value T) (T, error) {
	var public T
	data, err := json.Marshal(value)
	if err != nil {
		return public, err
	}
	if err = json.Unmarshal(data, &public); err != nil {
		return public, err
	}
	if err = visitSecrets(reflect.ValueOf(&public).Elem(), reflect.Value{}, nil, true); err != nil {
		return public, err
	}
	return public, nil
}

// MergeSecretUpdates only touches fields explicitly marked secret. It does not
// merge non-secret settings or resurrect deleted map entries (e.g. AI channels).
func MergeSecretUpdates(next, previous any, body json.RawMessage) error {
	n := reflect.ValueOf(next)
	if n.Kind() != reflect.Pointer || n.IsNil() {
		return nil
	}
	p := reflect.ValueOf(previous)
	var raw map[string]json.RawMessage
	if len(body) > 0 && string(body) != "null" {
		if err := json.Unmarshal(body, &raw); err != nil {
			return err
		}
	}
	return visitSecrets(n, p, raw, false)
}

func jsonField(raw map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	if v, ok := raw[name]; ok {
		return v, true
	}
	for key, v := range raw {
		if strings.EqualFold(key, name) {
			return v, true
		}
	}
	return nil, false
}

func indirect(v reflect.Value) reflect.Value {
	for v.IsValid() && v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return reflect.Value{}
		}
		v = v.Elem()
	}
	return v
}

func visitSecrets(next, previous reflect.Value, raw map[string]json.RawMessage, redact bool) error {
	next, previous = indirect(next), indirect(previous)
	if !next.IsValid() {
		return nil
	}
	switch next.Kind() {
	case reflect.Struct:
		for i := 0; i < next.NumField(); i++ {
			field := next.Type().Field(i)
			if field.PkgPath != "" {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			value := next.Field(i)
			old := reflect.Value{}
			if previous.IsValid() && previous.Type() == next.Type() {
				old = previous.Field(i)
			}
			input, present := jsonField(raw, name)
			if field.Tag.Get("secret") == "true" {
				if value.Kind() != reflect.String {
					return fmt.Errorf("secret %s must be a string", name)
				}
				if redact {
					if value.String() != "" {
						value.SetString(SecretMask)
					}
				} else if !present || value.String() == SecretMask {
					if old.IsValid() && old.String() != SecretMask {
						value.SetString(old.String())
					} else {
						if value.String() == SecretMask {
							return fmt.Errorf("%s has no saved secret; enter a new value", name)
						}
						value.SetString("")
					}
				}
				continue
			}
			var nested map[string]json.RawMessage
			if len(input) > 0 {
				_ = json.Unmarshal(input, &nested)
			}
			if err := visitSecrets(value, old, nested, redact); err != nil {
				return err
			}
		}
	case reflect.Map:
		if next.Type().Key().Kind() != reflect.String {
			return nil
		}
		for _, key := range next.MapKeys() {
			value := reflect.New(next.Type().Elem()).Elem()
			value.Set(next.MapIndex(key))
			old := reflect.Value{}
			if previous.IsValid() && previous.Type() == next.Type() {
				old = previous.MapIndex(key)
			}
			var nested map[string]json.RawMessage
			if data, ok := raw[key.String()]; ok {
				_ = json.Unmarshal(data, &nested)
			}
			if err := visitSecrets(value, old, nested, redact); err != nil {
				return err
			}
			next.SetMapIndex(key, value)
		}
	}
	return nil
}
