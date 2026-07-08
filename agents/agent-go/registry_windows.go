package agent

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// registryHive parses a hive prefix string into a registry.Key.
func registryHive(s string) (registry.Key, string, error) {
	upper := strings.ToUpper(s)
	for prefix, k := range map[string]registry.Key{
		"HKLM": registry.LOCAL_MACHINE,
		"HKCU": registry.CURRENT_USER,
		"HKCR": registry.CLASSES_ROOT,
		"HKU":  registry.USERS,
		"HKCC": registry.CURRENT_CONFIG,
	} {
		if strings.HasPrefix(upper, prefix+`\`) {
			return k, s[len(prefix)+1:], nil
		}
	}
	return 0, "", fmt.Errorf("unknown hive in %q — use HKLM, HKCU, HKCR, HKU, HKCC", s)
}

// regQuery reads a single value or lists a key's values.
// path format: HKLM\Software\...\KeyName  (value name is the last component if querying a value)
// To query the default value, use empty value name.
func regQuery(fullPath, valName string) (string, error) {
	hive, subkey, err := registryHive(fullPath)
	if err != nil {
		return "", err
	}
	k, err := registry.OpenKey(hive, subkey, registry.QUERY_VALUE|registry.READ)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", fullPath, err)
	}
	defer k.Close()

	// If no value name given, dump all values
	if valName == "" {
		names, err := k.ReadValueNames(-1)
		if err != nil {
			return "", fmt.Errorf("list values: %w", err)
		}
		var sb strings.Builder
		for _, n := range names {
			val, typ, err := k.GetValue(n, nil)
			_ = val
			if err != nil {
				continue
			}
			var disp string
			switch typ {
			case registry.SZ, registry.EXPAND_SZ:
				s, _, _ := k.GetStringValue(n)
				disp = fmt.Sprintf("REG_SZ    %s", s)
			case registry.DWORD:
				d, _, _ := k.GetIntegerValue(n)
				disp = fmt.Sprintf("REG_DWORD 0x%08X (%d)", d, d)
			case registry.QWORD:
				d, _, _ := k.GetIntegerValue(n)
				disp = fmt.Sprintf("REG_QWORD 0x%016X", d)
			case registry.MULTI_SZ:
				ss, _, _ := k.GetStringsValue(n)
				disp = fmt.Sprintf("REG_MULTI %s", strings.Join(ss, " | "))
			case registry.BINARY:
				b, _, _ := k.GetBinaryValue(n)
				disp = fmt.Sprintf("REG_BINARY %X", b)
			default:
				disp = fmt.Sprintf("type=%d", typ)
			}
			nm := n
			if nm == "" {
				nm = "(Default)"
			}
			sb.WriteString(fmt.Sprintf("  %-40s  %s\n", nm, disp))
		}
		return fmt.Sprintf("%s\n%s", fullPath, sb.String()), nil
	}

	s, _, err := k.GetStringValue(valName)
	if err == nil {
		return fmt.Sprintf("%s\\%s = %s", fullPath, valName, s), nil
	}
	d, _, err := k.GetIntegerValue(valName)
	if err == nil {
		return fmt.Sprintf("%s\\%s = 0x%X (%d)", fullPath, valName, d, d), nil
	}
	b, _, err := k.GetBinaryValue(valName)
	if err == nil {
		return fmt.Sprintf("%s\\%s = %X", fullPath, valName, b), nil
	}
	return "", fmt.Errorf("read value %q: %w", valName, err)
}

// regSet writes a REG_SZ value (or REG_DWORD if value parses as integer).
func regSet(fullPath, valName, value string) (string, error) {
	hive, subkey, err := registryHive(fullPath)
	if err != nil {
		return "", err
	}
	k, _, err := registry.CreateKey(hive, subkey, registry.SET_VALUE)
	if err != nil {
		return "", fmt.Errorf("create/open %s: %w", fullPath, err)
	}
	defer k.Close()
	if err := k.SetStringValue(valName, value); err != nil {
		return "", fmt.Errorf("set value: %w", err)
	}
	return fmt.Sprintf("set %s\\%s = %s", fullPath, valName, value), nil
}

// regDelete removes a named value, or the entire key (and all subkeys) if valName is empty.
func regDelete(fullPath, valName string) (string, error) {
	hive, subkey, err := registryHive(fullPath)
	if err != nil {
		return "", err
	}
	if valName != "" {
		k, err := registry.OpenKey(hive, subkey, registry.SET_VALUE)
		if err != nil {
			return "", fmt.Errorf("open %s: %w", fullPath, err)
		}
		defer k.Close()
		if err := k.DeleteValue(valName); err != nil {
			return "", fmt.Errorf("delete value %q: %w", valName, err)
		}
		return fmt.Sprintf("deleted value %s\\%s", fullPath, valName), nil
	}
	// Delete key recursively
	if err := registry.DeleteKey(hive, subkey); err != nil {
		return "", fmt.Errorf("delete key %s: %w", fullPath, err)
	}
	return fmt.Sprintf("deleted key %s", fullPath), nil
}

// regList enumerates subkeys of a key.
func regList(fullPath string) (string, error) {
	hive, subkey, err := registryHive(fullPath)
	if err != nil {
		return "", err
	}
	k, err := registry.OpenKey(hive, subkey, registry.ENUMERATE_SUB_KEYS|registry.READ)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", fullPath, err)
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", fmt.Errorf("list subkeys: %w", err)
	}
	if len(names) == 0 {
		return fullPath + "\n  (no subkeys)", nil
	}
	var sb strings.Builder
	sb.WriteString(fullPath + "\n")
	for _, n := range names {
		sb.WriteString("  " + n + "\n")
	}
	return sb.String(), nil
}
