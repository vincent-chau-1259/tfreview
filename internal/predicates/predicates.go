// Package predicates implements the Go predicates that rules refer to by
// name.
//
// Predicates read attribute values only through plan.Change.RawBefore and
// RawAfter, which refuse sensitive and unknown paths. Detail strings name
// paths and, where useful, non-sensitive numbers or booleans; never a value
// that could be secret.
package predicates

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"tfreview/internal/plan"
	"tfreview/internal/rules"
)

// Registry returns every predicate by the name used in rules files.
func Registry() rules.Registry {
	return rules.Registry{
		"changes_sensitive_attribute": ChangesSensitiveAttribute,
		"disables_encryption":         DisablesEncryption,
		"removes_deletion_protection": RemovesDeletionProtection,
		"reduces_backup_retention":    ReducesBackupRetention,
		"was_moved":                   WasMoved,
		"widens_network_access":       WidensNetworkAccess,
	}
}

// WasMoved is true when the change has a previous address.
func WasMoved(c plan.Change) (bool, string) {
	if c.PreviousAddress == "" {
		return false, ""
	}
	return true, "moved from " + c.PreviousAddress
}

// ChangesSensitiveAttribute is true when a sensitive value is written:
//   - update: a changed path is sensitive before or after;
//   - replace: any path sensitive after has a non-null value, changed or not,
//     since a replace rewrites every attribute;
//   - update and replace: a changed path ending in _wo_version, the companion
//     of a write-only attribute whose value is always null in plan JSON.
//
// It uses sensitivity markers only and never reads values.
func ChangesSensitiveAttribute(c plan.Change) (bool, string) {
	if c.Mode == "data" || (c.Action != plan.Update && c.Action != plan.Replace) {
		return false, ""
	}
	var written, wo []string
	for _, e := range c.Diff() {
		switch {
		case c.Action == plan.Update && e.Changed && e.Sensitive():
			written = append(written, e.Path)
		case c.Action == plan.Replace && e.AfterSensitive && e.After != "" && !e.AfterNull:
			written = append(written, e.Path)
		}
		if e.Changed && len(e.Segments) > 0 && strings.HasSuffix(lastKey(e.Segments), "_wo_version") {
			wo = append(wo, e.Path+" changed (write-only value will be rewritten)")
		}
	}
	var details []string
	if len(written) > 0 {
		details = append(details, "sensitive value written: "+strings.Join(written, ", "))
	}
	details = append(details, wo...)
	return len(details) > 0, strings.Join(details, "; ")
}

var encryptionFlags = map[string]bool{
	"storage_encrypted":          true, // RDS
	"encrypted":                  true, // EBS, EFS
	"at_rest_encryption_enabled": true, // ElastiCache
	"transit_encryption_enabled": true, // ElastiCache
}

var kmsKeys = map[string]bool{
	"kms_key_id":        true,
	"kms_key_arn":       true,
	"kms_master_key_id": true,
}

// DisablesEncryption is true when an encryption flag goes true to false, or
// a KMS key path goes from non-empty to empty, null or removed.
func DisablesEncryption(c plan.Change) (bool, string) {
	var found []string
	for _, e := range c.Diff() {
		if !e.Changed {
			continue
		}
		key := lastKey(e.Segments)
		switch {
		case encryptionFlags[key]:
			if boolTransition(c, e.Segments, true, false) {
				found = append(found, e.Path+": true -> false")
			}
		case kmsKeys[key]:
			if nonEmptyBefore(c, e.Segments) && emptyAfter(c, e) {
				found = append(found, e.Path+" removed")
			}
		}
	}
	return detail(found)
}

// RemovesDeletionProtection is true when deletion_protection,
// deletion_protection_enabled or enable_deletion_protection goes true to
// false, or force_destroy goes false to true.
func RemovesDeletionProtection(c plan.Change) (bool, string) {
	var found []string
	for _, e := range c.Diff() {
		if !e.Changed {
			continue
		}
		switch lastKey(e.Segments) {
		case "deletion_protection", "deletion_protection_enabled", "enable_deletion_protection":
			if boolTransition(c, e.Segments, true, false) {
				found = append(found, e.Path+": true -> false")
			}
		case "force_destroy":
			if boolTransition(c, e.Segments, false, true) {
				found = append(found, e.Path+": false -> true")
			}
		}
	}
	return detail(found)
}

// ReducesBackupRetention is true when backup_retention_period or
// snapshot_retention_limit decreases, skip_final_snapshot or
// delete_automated_backups goes false to true, or
// point_in_time_recovery.N.enabled goes true to false. A decrease to 0 is
// called out in the detail, since it disables automated backups.
func ReducesBackupRetention(c plan.Change) (bool, string) {
	var found []string
	for _, e := range c.Diff() {
		if !e.Changed {
			continue
		}
		segs := e.Segments
		switch lastKey(segs) {
		case "backup_retention_period", "snapshot_retention_limit":
			before, ok1 := number(c.RawBefore(segs))
			after, ok2 := number(c.RawAfter(segs))
			if ok1 && ok2 && after < before {
				d := fmt.Sprintf("%s: %s -> %s", e.Path, fmtNum(before), fmtNum(after))
				if after == 0 {
					d += " (backups disabled)"
				}
				found = append(found, d)
			}
		case "skip_final_snapshot", "delete_automated_backups":
			if boolTransition(c, segs, false, true) {
				found = append(found, e.Path+": false -> true")
			}
		case "enabled":
			if len(segs) >= 3 && segs[len(segs)-3] == "point_in_time_recovery" &&
				boolTransition(c, segs, true, false) {
				found = append(found, e.Path+": true -> false")
			}
		}
	}
	return detail(found)
}

func detail(found []string) (bool, string) {
	return len(found) > 0, strings.Join(found, "; ")
}

// lastKey returns the last string segment of a path, or "".
func lastKey(segs []any) string {
	if len(segs) == 0 {
		return ""
	}
	s, _ := segs[len(segs)-1].(string)
	return s
}

func boolTransition(c plan.Change, path []any, from, to bool) bool {
	b, ok1 := asBool(c.RawBefore(path))
	a, ok2 := asBool(c.RawAfter(path))
	return ok1 && ok2 && b == from && a == to
}

// asBool accepts JSON booleans and the strings "true"/"false", which some
// provider attributes use.
func asBool(v any, ok bool) (bool, bool) {
	if !ok {
		return false, false
	}
	switch b := v.(type) {
	case bool:
		return b, true
	case string:
		p, err := strconv.ParseBool(b)
		return p, err == nil
	}
	return false, false
}

func number(v any, ok bool) (float64, bool) {
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	return 0, false
}

func fmtNum(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func nonEmptyBefore(c plan.Change, path []any) bool {
	v, ok := c.RawBefore(path)
	s, isStr := v.(string)
	return ok && isStr && s != ""
}

// emptyAfter is true when the path is "" or null after, or was removed with
// its block (absent after, on a change that still has an after value).
func emptyAfter(c plan.Change, e plan.DiffEntry) bool {
	if e.Unknown || c.After == nil {
		return false
	}
	v, ok := c.RawAfter(e.Segments)
	if !ok {
		return e.After == "" // absent; sensitive or unknown paths return early above or are not empty
	}
	return v == nil || v == ""
}
