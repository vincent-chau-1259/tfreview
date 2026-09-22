// Package plan parses `terraform show -json` output into a domain model.
package plan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrEmptyInput is returned by Parse when the input is empty or whitespace.
var ErrEmptyInput = errors.New("empty plan input")

// Plan is a parsed plan.
type Plan struct {
	FormatVersion    string
	TerraformVersion string

	// Errored is true when Terraform reported that planning failed.
	Errored bool
	// Complete is false when the plan is partial (for example with deferred
	// changes). Plans from Terraform versions that omit the field are complete.
	Complete bool

	Changes []Change

	// Warnings are parse-level warnings, such as unrecognised action
	// combinations. They never contain attribute values.
	Warnings []string
}

// Change is one entry of resource_changes.
type Change struct {
	Address             string
	PreviousAddress     string // set for moved resources
	ModuleAddress       string
	Mode                string // managed | data
	Type                string
	Name                string
	Index               any // int, string, or nil
	ProviderName        string
	Action              Action
	RawActions          []string // original actions array, kept for Unknown
	CreateBeforeDestroy bool     // actions == ["create","delete"]
	ActionReason        string
	ReplacePaths        [][]any // path elements may be strings or ints
	Before, After       any
	AfterUnknown        any // bool or nested mirror of After
	BeforeSensitive     any // bool or nested mirror of Before
	AfterSensitive      any // bool or nested mirror of After
	Deposed             string
}

type rawPlan struct {
	FormatVersion    string              `json:"format_version"`
	TerraformVersion string              `json:"terraform_version"`
	Errored          bool                `json:"errored"`
	Complete         *bool               `json:"complete"`
	ResourceChanges  []rawResourceChange `json:"resource_changes"`
}

type rawResourceChange struct {
	Address         string `json:"address"`
	PreviousAddress string `json:"previous_address"`
	ModuleAddress   string `json:"module_address"`
	Mode            string `json:"mode"`
	Type            string `json:"type"`
	Name            string `json:"name"`
	Index           any    `json:"index"`
	ProviderName    string `json:"provider_name"`
	Deposed         string `json:"deposed"`
	ActionReason    string `json:"action_reason"`
	Change          struct {
		Actions         []string `json:"actions"`
		Before          any      `json:"before"`
		After           any      `json:"after"`
		AfterUnknown    any      `json:"after_unknown"`
		BeforeSensitive any      `json:"before_sensitive"`
		AfterSensitive  any      `json:"after_sensitive"`
		ReplacePaths    [][]any  `json:"replace_paths"`
	} `json:"change"`
}

// Parse reads plan JSON from r.
func Parse(r io.Reader) (*Plan, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading plan: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, ErrEmptyInput
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw rawPlan
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("invalid plan JSON: %w", err)
	}
	// Decode stops after one value; anything after it (a second document,
	// log lines from a wrapper) means the input is not a single plan.
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("invalid plan JSON: unexpected data after the plan document")
	}
	if err := checkFormatVersion(raw.FormatVersion); err != nil {
		return nil, err
	}

	p := &Plan{
		FormatVersion:    raw.FormatVersion,
		TerraformVersion: raw.TerraformVersion,
		Errored:          raw.Errored,
		Complete:         raw.Complete == nil || *raw.Complete,
		Changes:          make([]Change, 0, len(raw.ResourceChanges)),
	}
	for _, rc := range raw.ResourceChanges {
		c := Change{
			Address:         rc.Address,
			PreviousAddress: rc.PreviousAddress,
			ModuleAddress:   rc.ModuleAddress,
			Mode:            rc.Mode,
			Type:            rc.Type,
			Name:            rc.Name,
			Index:           normIndex(rc.Index),
			ProviderName:    rc.ProviderName,
			RawActions:      rc.Change.Actions,
			ActionReason:    rc.ActionReason,
			ReplacePaths:    normPaths(rc.Change.ReplacePaths),
			Before:          rc.Change.Before,
			After:           rc.Change.After,
			AfterUnknown:    rc.Change.AfterUnknown,
			BeforeSensitive: rc.Change.BeforeSensitive,
			AfterSensitive:  rc.Change.AfterSensitive,
			Deposed:         rc.Deposed,
		}
		var ok bool
		c.Action, c.CreateBeforeDestroy, ok = MapActions(rc.Change.Actions)
		if !ok {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"%s: unrecognised actions %q; treated as unknown and flagged for attention",
				rc.Address, rc.Change.Actions))
		}
		p.Changes = append(p.Changes, c)
	}
	return p, nil
}

func checkFormatVersion(v string) error {
	if v == "" {
		return errors.New("invalid plan JSON: missing format_version (is this `terraform show -json` output?)")
	}
	major, _, _ := strings.Cut(v, ".")
	if major != "1" {
		return fmt.Errorf("unsupported plan format_version %q: tfreview supports 1.x", v)
	}
	return nil
}

// normIndex converts a JSON-decoded instance key to int, string or nil.
func normIndex(v any) any {
	if n, ok := v.(json.Number); ok {
		if i, err := strconv.Atoi(string(n)); err == nil {
			return i
		}
		return string(n)
	}
	return v
}

func normPaths(paths [][]any) [][]any {
	for _, p := range paths {
		for i, seg := range p {
			p[i] = normIndex(seg)
		}
	}
	return paths
}
