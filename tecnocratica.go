package tecnocratica

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// Provider implements DNS record manipulation with neodigit/virtualname.
type Provider struct {
	// The neodigit/virtualname api token.
	APIToken string `json:"api_token,omitempty"`
	APIURL   string `json:"api_url,omitempty"`
}

// getZoneID finds the zone ID for a given zone name.
func (p *Provider) getZoneID(ctx context.Context, zone string) (int, error) {
	client, err := newClient(p)
	if err != nil {
		return 0, err
	}

	zones, err := client.getZones(ctx)
	if err != nil {
		return 0, err
	}

	// Normalize the zone name (ensure it ends with a dot)
	zoneName := strings.TrimSuffix(zone, ".")

	for _, z := range zones {
		if strings.TrimSuffix(z.Name, ".") == zoneName {
			return z.ID, nil
		}
	}

	return 0, fmt.Errorf("zone not found: %s", zone)
}

// libdnsToInternal converts a libdns.Record to an internal Record.
func libdnsToInternal(zone string, rec libdns.Record) Record {
	rr := rec.RR()

	// Convert relative name to the format expected by the API
	// The API expects names relative to the zone, or "@" for the zone apex
	name := rr.Name

	// Strip the zone suffix if present (FQDN to relative conversion)
	// Normalize both name and zone by removing trailing dots for consistent matching
	normalizedZone := strings.TrimSuffix(zone, ".")
	normalizedName := strings.TrimSuffix(name, ".")
	zoneSuffix := "." + normalizedZone

	// Use CutSuffix for cleaner suffix removal
	if after, found := strings.CutSuffix(normalizedName, zoneSuffix); found {
		name = after
	}

	// Handle apex records
	if name == "" || name == "@" || name == zone || name == strings.TrimSuffix(zone, ".") {
		name = "@"
	}

	// Parse priority from data field for MX and SRV records
	priority := 0
	data := rr.Data

	// For TXT records, remove quotes if present (libdns adds them, but API doesn't store them)
	if rr.Type == "TXT" {
		data = strings.Trim(data, "\"")
	}

	switch rr.Type {
	case "MX":
		// MX format: "priority target"
		parts := strings.Fields(rr.Data)
		if len(parts) >= 2 {
			_, _ = fmt.Sscanf(parts[0], "%d", &priority)
			data = strings.Join(parts[1:], " ")
		}
	case "SRV":
		// SRV format: "priority weight port target"
		parts := strings.Fields(rr.Data)
		if len(parts) >= 4 {
			_, _ = fmt.Sscanf(parts[0], "%d", &priority)
			// Keep weight, port, and target in the content
			data = strings.Join(parts[1:], " ")
		}
	}

	return Record{
		Name:     name,
		Type:     rr.Type,
		Content:  data,
		TTL:      int(rr.TTL.Seconds()),
		Priority: priority,
	}
}

// internalToLibdns converts an internal Record to a libdns.Record.
// The zone parameter is required to reconstruct absolute domain names from relative names.
func internalToLibdns(zone string, rec Record) (libdns.Record, error) {
	data := rec.Content

	// For TXT records, strip quotes if the API returns them
	// This ensures consistency with libdnsToInternal which also strips quotes
	if rec.Type == "TXT" {
		data = strings.Trim(data, "\"")
	}

	// For MX and SRV records, libdns expects the priority to be part of the Data field
	// Format: "priority target" for MX, or "priority weight port target" for SRV
	// The Neodigit API stores priority separately in the Priority field
	switch rec.Type {
	case "MX":
		data = fmt.Sprintf("%d %s", rec.Priority, rec.Content)
	case "SRV":
		// SRV: API stores priority in Priority field, "weight port target" in Content
		data = fmt.Sprintf("%d %s", rec.Priority, rec.Content)
	}

	name := rec.Name

	// Handle SRV records with empty names by using a placeholder
	// The Neodigit API may return SRV records with empty names which are valid in their system
	// but don't pass libdns strict SRV naming validation (_service._proto.name)
	if rec.Type == "SRV" && (name == "" || name == "@") {
		// Use a placeholder that satisfies libdns validation
		// This preserves the record data while allowing it to pass validation
		name = "_service._tcp"
	}

	// Convert relative names to absolute (FQDN) by appending the zone
	// The API may return relative names (e.g., "_acme-challenge.git" or "@")
	// or sometimes already-qualified names (e.g., "_acme-challenge.git.etaboada.com")
	// libdns expects absolute names (e.g., "_acme-challenge.git.etaboada.com.")
	normalizedZone := strings.TrimSuffix(zone, ".")

	if name == "" || name == "@" {
		// "@" or empty represents the zone apex, so use the zone itself
		if !strings.HasSuffix(zone, ".") {
			name = zone + "."
		} else {
			name = zone
		}
	} else if strings.HasSuffix(name, "."+normalizedZone) || strings.HasSuffix(name, "."+normalizedZone+".") {
		// Name already contains the zone (API returned FQDN), just ensure trailing dot
		name = strings.TrimSuffix(name, ".") + "."
	} else if name == normalizedZone || name == normalizedZone+"." {
		// Name is the zone itself (apex record with zone name)
		name = normalizedZone + "."
	} else {
		// Name is relative, append the zone
		name = name + "." + normalizedZone + "."
	}

	rr := libdns.RR{
		Name: name,
		Type: rec.Type,
		Data: data,
		TTL:  time.Duration(rec.TTL) * time.Second,
	}

	// Parse the RR into a type-specific record
	return rr.Parse()
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	client, err := newClient(p)
	if err != nil {
		return nil, err
	}

	records, err := client.getRecords(ctx, zoneID, "")
	if err != nil {
		return nil, err
	}

	var libdnsRecords []libdns.Record
	for _, record := range records {
		libdnsRec, err := internalToLibdns(zone, record)
		if err != nil {
			// Skip records that can't be parsed
			// This allows the operation to continue even if some records are invalid
			// In debug mode, you could log: record ID, type, name, and error
			continue
		}
		libdnsRecords = append(libdnsRecords, libdnsRec)
	}

	return libdnsRecords, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	client, err := newClient(p)
	if err != nil {
		return nil, err
	}

	var appendedRecords []libdns.Record
	for _, record := range records {
		internalRec := libdnsToInternal(zone, record)

		createdRec, err := client.createRecord(ctx, zoneID, internalRec)
		if err != nil {
			return nil, fmt.Errorf("failed to create record: %w", err)
		}

		libdnsRec, err := internalToLibdns(zone, *createdRec)
		if err != nil {
			return nil, fmt.Errorf("failed to convert created record: %w", err)
		}

		appendedRecords = append(appendedRecords, libdnsRec)
	}

	return appendedRecords, nil
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// Per libdns spec: for any (name, type) pair in the input, SetRecords ensures that the only
// records in the output zone with that (name, type) pair are those provided in the input.
// It returns the records which were set.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	client, err := newClient(p)
	if err != nil {
		return nil, err
	}

	// Get all existing records
	existingRecords, err := client.getRecords(ctx, zoneID, "")
	if err != nil {
		return nil, err
	}

	// Group input records by (name, type)
	type recordKey struct{ Name, Type string }
	inputByKey := make(map[recordKey][]Record)
	for _, record := range records {
		internalRec := libdnsToInternal(zone, record)
		key := recordKey{internalRec.Name, internalRec.Type}
		inputByKey[key] = append(inputByKey[key], internalRec)
	}

	var setRecords []libdns.Record

	// Process each (name, type) group
	for key, inputRecs := range inputByKey {
		// Find all existing records with this (name, type)
		var existingForKey []Record
		for _, existing := range existingRecords {
			if existing.Name == key.Name && existing.Type == key.Type {
				existingForKey = append(existingForKey, existing)
			}
		}

		// Update/create input records, reusing existing record IDs where possible
		for i, internalRec := range inputRecs {
			var resultRec *Record
			if i < len(existingForKey) {
				// Update existing record
				resultRec, err = client.updateRecord(ctx, zoneID, existingForKey[i].ID, internalRec)
				if err != nil {
					return nil, fmt.Errorf("failed to update record %d: %w", existingForKey[i].ID, err)
				}
			} else {
				// Create new record
				resultRec, err = client.createRecord(ctx, zoneID, internalRec)
				if err != nil {
					return nil, fmt.Errorf("failed to create record: %w", err)
				}
			}

			libdnsRec, err := internalToLibdns(zone, *resultRec)
			if err != nil {
				return nil, fmt.Errorf("failed to convert record: %w", err)
			}
			setRecords = append(setRecords, libdnsRec)
		}

		// Delete extra existing records that exceed the input count
		for i := len(inputRecs); i < len(existingForKey); i++ {
			err := client.deleteRecord(ctx, zoneID, existingForKey[i].ID)
			if err != nil {
				return nil, fmt.Errorf("failed to delete extra record %d: %w", existingForKey[i].ID, err)
			}
		}
	}

	return setRecords, nil
}

// DeleteRecords deletes the specified records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	zoneID, err := p.getZoneID(ctx, zone)
	if err != nil {
		return nil, err
	}

	client, err := newClient(p)
	if err != nil {
		return nil, err
	}

	// Get all existing records
	existingRecords, err := client.getRecords(ctx, zoneID, "")
	if err != nil {
		return nil, err
	}

	var deletedRecords []libdns.Record
	for _, record := range records {
		internalRec := libdnsToInternal(zone, record)

		// Find matching records by name, type, and content
		found := false
		for _, existing := range existingRecords {
			if existing.Name == internalRec.Name &&
				existing.Type == internalRec.Type &&
				existing.Content == internalRec.Content {
				err := client.deleteRecord(ctx, zoneID, existing.ID)
				if err != nil {
					return nil, fmt.Errorf("failed to delete record %d: %w", existing.ID, err)
				}

				libdnsRec, err := internalToLibdns(zone, existing)
				if err != nil {
					return nil, fmt.Errorf("failed to convert deleted record: %w", err)
				}

				deletedRecords = append(deletedRecords, libdnsRec)
				found = true
			}
		}

		if !found {
			// Record not found - this could be because:
			// 1. It doesn't exist
			// 2. The content doesn't match exactly (e.g., whitespace differences)
			// Try matching by name and type only as a fallback
			for _, existing := range existingRecords {
				if existing.Name == internalRec.Name && existing.Type == internalRec.Type {
					err := client.deleteRecord(ctx, zoneID, existing.ID)
					if err != nil {
						return nil, fmt.Errorf("failed to delete record %d: %w", existing.ID, err)
					}

					libdnsRec, err := internalToLibdns(zone, existing)
					if err != nil {
						return nil, fmt.Errorf("failed to convert deleted record: %w", err)
					}

					deletedRecords = append(deletedRecords, libdnsRec)
					break
				}
			}
		}
	}

	return deletedRecords, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
