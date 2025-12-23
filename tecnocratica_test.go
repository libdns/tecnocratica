package tecnocratica

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

func TestLibdnsToInternal(t *testing.T) {
	tests := []struct {
		name         string
		zone         string
		rr           libdns.RR
		wantName     string
		wantType     string
		wantData     string
		wantTTL      int
		wantPriority int
	}{
		{
			name: "simple A record",
			zone: "example.com",
			rr: libdns.RR{
				Type: "A",
				Name: "www",
				Data: "192.0.2.1",
				TTL:  3600 * time.Second,
			},
			wantName:     "www",
			wantType:     "A",
			wantData:     "192.0.2.1",
			wantTTL:      3600,
			wantPriority: 0,
		},
		{
			name: "apex record with @",
			zone: "example.com",
			rr: libdns.RR{
				Type: "A",
				Name: "@",
				Data: "192.0.2.1",
				TTL:  3600 * time.Second,
			},
			wantName:     "@",
			wantType:     "A",
			wantData:     "192.0.2.1",
			wantTTL:      3600,
			wantPriority: 0,
		},
		{
			name: "apex record with empty name",
			zone: "example.com",
			rr: libdns.RR{
				Type: "A",
				Name: "",
				Data: "192.0.2.1",
				TTL:  3600 * time.Second,
			},
			wantName:     "@",
			wantType:     "A",
			wantData:     "192.0.2.1",
			wantTTL:      3600,
			wantPriority: 0,
		},
		{
			name: "CNAME record",
			zone: "example.com",
			rr: libdns.RR{
				Type: "CNAME",
				Name: "www",
				Data: "example.com.",
				TTL:  3600 * time.Second,
			},
			wantName:     "www",
			wantType:     "CNAME",
			wantData:     "example.com.",
			wantTTL:      3600,
			wantPriority: 0,
		},
		{
			name: "TXT record",
			zone: "example.com",
			rr: libdns.RR{
				Type: "TXT",
				Name: "_acme-challenge",
				Data: "validation-token-here",
				TTL:  300 * time.Second,
			},
			wantName:     "_acme-challenge",
			wantType:     "TXT",
			wantData:     "validation-token-here",
			wantTTL:      300,
			wantPriority: 0,
		},
		{
			name: "MX record",
			zone: "example.com",
			rr: libdns.RR{
				Type: "MX",
				Name: "@",
				Data: "10 mail.example.com",
				TTL:  3600 * time.Second,
			},
			wantName:     "@",
			wantType:     "MX",
			wantData:     "mail.example.com",
			wantTTL:      3600,
			wantPriority: 10,
		},
		{
			name: "SRV record",
			zone: "example.com",
			rr: libdns.RR{
				Type: "SRV",
				Name: "_sip._tcp",
				Data: "10 20 5060 sip.example.com",
				TTL:  3600 * time.Second,
			},
			wantName:     "_sip._tcp",
			wantType:     "SRV",
			wantData:     "20 5060 sip.example.com",
			wantTTL:      3600,
			wantPriority: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, err := tt.rr.Parse()
			if err != nil {
				t.Fatalf("Failed to parse RR: %v", err)
			}

			result := libdnsToInternal(tt.zone, rec)

			if result.Name != tt.wantName {
				t.Errorf("Name = %v, want %v", result.Name, tt.wantName)
			}
			if result.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", result.Type, tt.wantType)
			}
			if result.Content != tt.wantData {
				t.Errorf("Content = %v, want %v", result.Content, tt.wantData)
			}
			if result.TTL != tt.wantTTL {
				t.Errorf("TTL = %v, want %v", result.TTL, tt.wantTTL)
			}
			if result.Priority != tt.wantPriority {
				t.Errorf("Priority = %v, want %v", result.Priority, tt.wantPriority)
			}
		})
	}
}

func TestInternalToLibdns(t *testing.T) {
	tests := []struct {
		name      string
		record    Record
		wantName  string
		wantType  string
		wantValue string
		wantTTL   time.Duration
		wantErr   bool
	}{
		{
			name: "A record",
			record: Record{
				ID:      1,
				Name:    "www",
				Type:    "A",
				Content: "192.0.2.1",
				TTL:     3600,
			},
			wantName:  "www",
			wantType:  "A",
			wantValue: "192.0.2.1",
			wantTTL:   3600 * time.Second,
			wantErr:   false,
		},
		{
			name: "AAAA record",
			record: Record{
				ID:      2,
				Name:    "www",
				Type:    "AAAA",
				Content: "2001:db8::1",
				TTL:     3600,
			},
			wantName:  "www",
			wantType:  "AAAA",
			wantValue: "2001:db8::1",
			wantTTL:   3600 * time.Second,
			wantErr:   false,
		},
		{
			name: "TXT record",
			record: Record{
				ID:      3,
				Name:    "_acme-challenge",
				Type:    "TXT",
				Content: "validation-token",
				TTL:     300,
			},
			wantName:  "_acme-challenge",
			wantType:  "TXT",
			wantValue: "validation-token",
			wantTTL:   300 * time.Second,
			wantErr:   false,
		},
		{
			name: "MX record",
			record: Record{
				ID:       4,
				Name:     "@",
				Type:     "MX",
				Content:  "mail.example.com",
				TTL:      3600,
				Priority: 10,
			},
			wantName:  "@",
			wantType:  "MX",
			wantValue: "10 mail.example.com",
			wantTTL:   3600 * time.Second,
			wantErr:   false,
		},
		{
			name: "SRV record",
			record: Record{
				ID:       5,
				Name:     "_sip._tcp",
				Type:     "SRV",
				Content:  "20 5060 sip.example.com",
				TTL:      3600,
				Priority: 10,
			},
			wantName:  "_sip._tcp",
			wantType:  "SRV",
			wantValue: "10 20 5060 sip.example.com",
			wantTTL:   3600 * time.Second,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := internalToLibdns(tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("internalToLibdns() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				rr := result.RR()
				if rr.Name != tt.wantName {
					t.Errorf("Name = %v, want %v", rr.Name, tt.wantName)
				}
				if rr.Type != tt.wantType {
					t.Errorf("Type = %v, want %v", rr.Type, tt.wantType)
				}
				if rr.Data != tt.wantValue {
					t.Errorf("Data = %v, want %v", rr.Data, tt.wantValue)
				}
				if rr.TTL != tt.wantTTL {
					t.Errorf("TTL = %v, want %v", rr.TTL, tt.wantTTL)
				}
			}
		})
	}
}

func TestProvider_GetZoneID(t *testing.T) {
	tests := []struct {
		name     string
		zoneName string
		zones    []Zone
		wantID   int
		wantErr  bool
	}{
		{
			name:     "zone found without trailing dot",
			zoneName: "example.com",
			zones: []Zone{
				{ID: 1, Name: "example.com"},
				{ID: 2, Name: "example.org"},
			},
			wantID:  1,
			wantErr: false,
		},
		{
			name:     "zone found with trailing dot",
			zoneName: "example.com.",
			zones: []Zone{
				{ID: 1, Name: "example.com"},
				{ID: 2, Name: "example.org"},
			},
			wantID:  1,
			wantErr: false,
		},
		{
			name:     "zone not found",
			zoneName: "notfound.com",
			zones: []Zone{
				{ID: 1, Name: "example.com"},
				{ID: 2, Name: "example.org"},
			},
			wantID:  0,
			wantErr: true,
		},
		{
			name:     "empty zones list",
			zoneName: "example.com",
			zones:    []Zone{},
			wantID:   0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(tt.zones)
			}))
			defer server.Close()

			p := &Provider{
				APIToken: "test-token",
				APIURL:   server.URL,
			}

			zoneID, err := p.getZoneID(context.Background(), tt.zoneName)
			if (err != nil) != tt.wantErr {
				t.Errorf("getZoneID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && zoneID != tt.wantID {
				t.Errorf("getZoneID() = %v, want %v", zoneID, tt.wantID)
			}
		})
	}
}

func TestProvider_GetRecords(t *testing.T) {
	tests := []struct {
		name      string
		zoneName  string
		zones     []Zone
		records   []Record
		wantErr   bool
		wantCount int
	}{
		{
			name:     "get all records",
			zoneName: "example.com",
			zones: []Zone{
				{ID: 1, Name: "example.com"},
			},
			records: []Record{
				{ID: 1, Name: "www", Type: "A", Content: "192.0.2.1", TTL: 3600},
				{ID: 2, Name: "mail", Type: "A", Content: "192.0.2.2", TTL: 3600},
			},
			wantErr:   false,
			wantCount: 2,
		},
		{
			name:      "zone not found",
			zoneName:  "notfound.com",
			zones:     []Zone{},
			records:   []Record{},
			wantErr:   true,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/dns/zones" {
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(tt.zones)
				} else {
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(tt.records)
				}
			}))
			defer server.Close()

			p := &Provider{
				APIToken: "test-token",
				APIURL:   server.URL,
			}

			records, err := p.GetRecords(context.Background(), tt.zoneName)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(records) != tt.wantCount {
				t.Errorf("GetRecords() returned %d records, want %d", len(records), tt.wantCount)
			}
		})
	}
}

func TestProvider_AppendRecords(t *testing.T) {
	makeRecord := func(name, typ, data string, ttl time.Duration) libdns.Record {
		rr := libdns.RR{
			Name: name,
			Type: typ,
			Data: data,
			TTL:  ttl,
		}
		rec, _ := rr.Parse()
		return rec
	}

	tests := []struct {
		name       string
		zoneName   string
		zones      []Zone
		newRecords []libdns.Record
		wantErr    bool
		wantCount  int
	}{
		{
			name:     "append single record",
			zoneName: "example.com",
			zones: []Zone{
				{ID: 1, Name: "example.com"},
			},
			newRecords: []libdns.Record{
				makeRecord("test", "A", "192.0.2.1", 3600*time.Second),
			},
			wantErr:   false,
			wantCount: 1,
		},
		{
			name:     "append multiple records",
			zoneName: "example.com",
			zones: []Zone{
				{ID: 1, Name: "example.com"},
			},
			newRecords: []libdns.Record{
				makeRecord("test1", "A", "192.0.2.1", 3600*time.Second),
				makeRecord("test2", "A", "192.0.2.2", 3600*time.Second),
			},
			wantErr:   false,
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recordID := 1
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/dns/zones" {
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(tt.zones)
				} else if r.Method == http.MethodPost {
					var req RecordRequest
					json.NewDecoder(r.Body).Decode(&req)
					req.Record.ID = recordID
					recordID++
					w.WriteHeader(http.StatusCreated)
					json.NewEncoder(w).Encode(req.Record)
				}
			}))
			defer server.Close()

			p := &Provider{
				APIToken: "test-token",
				APIURL:   server.URL,
			}

			records, err := p.AppendRecords(context.Background(), tt.zoneName, tt.newRecords)
			if (err != nil) != tt.wantErr {
				t.Errorf("AppendRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(records) != tt.wantCount {
				t.Errorf("AppendRecords() returned %d records, want %d", len(records), tt.wantCount)
			}
		})
	}
}

func TestProvider_SetRecords(t *testing.T) {
	makeRecord := func(name, typ, data string, ttl time.Duration) libdns.Record {
		rr := libdns.RR{
			Name: name,
			Type: typ,
			Data: data,
			TTL:  ttl,
		}
		rec, _ := rr.Parse()
		return rec
	}

	tests := []struct {
		name            string
		zoneName        string
		zones           []Zone
		existingRecords []Record
		newRecords      []libdns.Record
		wantErr         bool
		wantCount       int
	}{
		{
			name:     "set replaces existing record",
			zoneName: "example.com",
			zones: []Zone{
				{ID: 1, Name: "example.com"},
			},
			existingRecords: []Record{
				{ID: 1, Name: "www", Type: "A", Content: "192.0.2.1", TTL: 3600},
			},
			newRecords: []libdns.Record{
				makeRecord("www", "A", "192.0.2.100", 7200*time.Second),
			},
			wantErr:   false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recordID := 100
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/dns/zones" {
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(tt.zones)
				} else if r.Method == http.MethodGet {
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(tt.existingRecords)
				} else if r.Method == http.MethodDelete {
					w.WriteHeader(http.StatusNoContent)
				} else if r.Method == http.MethodPost {
					var req RecordRequest
					json.NewDecoder(r.Body).Decode(&req)
					req.Record.ID = recordID
					recordID++
					w.WriteHeader(http.StatusCreated)
					json.NewEncoder(w).Encode(req.Record)
				}
			}))
			defer server.Close()

			p := &Provider{
				APIToken: "test-token",
				APIURL:   server.URL,
			}

			records, err := p.SetRecords(context.Background(), tt.zoneName, tt.newRecords)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(records) != tt.wantCount {
				t.Errorf("SetRecords() returned %d records, want %d", len(records), tt.wantCount)
			}
		})
	}
}

func TestProvider_DeleteRecords(t *testing.T) {
	makeRecord := func(name, typ, data string, ttl time.Duration) libdns.Record {
		rr := libdns.RR{
			Name: name,
			Type: typ,
			Data: data,
			TTL:  ttl,
		}
		rec, _ := rr.Parse()
		return rec
	}

	tests := []struct {
		name            string
		zoneName        string
		zones           []Zone
		existingRecords []Record
		deleteRecords   []libdns.Record
		wantErr         bool
		wantCount       int
	}{
		{
			name:     "delete existing record",
			zoneName: "example.com",
			zones: []Zone{
				{ID: 1, Name: "example.com"},
			},
			existingRecords: []Record{
				{ID: 1, Name: "www", Type: "A", Content: "192.0.2.1", TTL: 3600},
				{ID: 2, Name: "mail", Type: "A", Content: "192.0.2.2", TTL: 3600},
			},
			deleteRecords: []libdns.Record{
				makeRecord("www", "A", "192.0.2.1", 3600*time.Second),
			},
			wantErr:   false,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/dns/zones" {
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(tt.zones)
				} else if r.Method == http.MethodGet {
					w.WriteHeader(http.StatusOK)
					json.NewEncoder(w).Encode(tt.existingRecords)
				} else if r.Method == http.MethodDelete {
					w.WriteHeader(http.StatusNoContent)
				}
			}))
			defer server.Close()

			p := &Provider{
				APIToken: "test-token",
				APIURL:   server.URL,
			}

			records, err := p.DeleteRecords(context.Background(), tt.zoneName, tt.deleteRecords)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeleteRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(records) != tt.wantCount {
				t.Errorf("DeleteRecords() returned %d records, want %d", len(records), tt.wantCount)
			}
		})
	}
}

// Integration tests - only run if environment variables are set
func TestIntegration_GetRecords(t *testing.T) {
	apiToken := os.Getenv("NEODIGIT_TOKEN")
	testDomain := os.Getenv("NEODIGIT_DOMAIN")

	if apiToken == "" || testDomain == "" {
		t.Skip("Skipping integration test - set NEODIGIT_TOKEN and NEODIGIT_DOMAIN to run")
	}

	p := &Provider{
		APIToken: apiToken,
	}

	records, err := p.GetRecords(context.Background(), testDomain)
	if err != nil {
		t.Errorf("Integration test GetRecords() failed: %v", err)
		return
	}

	t.Logf("Successfully retrieved %d records from zone %s", len(records), testDomain)
}

func TestIntegration_AppendAndDelete(t *testing.T) {
	apiToken := os.Getenv("NEODIGIT_TOKEN")
	testDomain := os.Getenv("NEODIGIT_DOMAIN")

	if apiToken == "" || testDomain == "" {
		t.Skip("Skipping integration test - set NEODIGIT_API_TOKEN and NEODIGIT_TEST_ZONE to run")
	}

	p := &Provider{
		APIToken: apiToken,
	}

	// Create a test record
	rr := libdns.RR{
		Type: "TXT",
		Name: "_libdns-test",
		Data: "integration-test-record",
		TTL:  300 * time.Second,
	}
	rec, err := rr.Parse()
	if err != nil {
		t.Fatalf("Failed to create test record: %v", err)
	}
	testRecord := []libdns.Record{rec}

	// Clean up any existing test record from previous failed runs
	t.Logf("Cleaning up any existing test records...")
	_, _ = p.DeleteRecords(context.Background(), testDomain, testRecord)

	// Append the record
	appended, err := p.AppendRecords(context.Background(), testDomain, testRecord)
	if err != nil {
		t.Fatalf("Integration test AppendRecords() failed: %v", err)
	}

	// Ensure cleanup happens even if the test fails
	defer func() {
		deleted, err := p.DeleteRecords(context.Background(), testDomain, appended)
		if err != nil {
			t.Errorf("Failed to clean up test record: %v", err)
		} else if len(deleted) > 0 {
			t.Logf("Cleaned up %d test record(s)", len(deleted))
		}
	}()

	if len(appended) != 1 {
		t.Fatalf("Expected 1 appended record, got %d", len(appended))
	}

	t.Logf("Successfully created test record with ID")

	// Verify the record was created by fetching all records
	allRecords, err := p.GetRecords(context.Background(), testDomain)
	if err != nil {
		t.Errorf("Failed to fetch records for verification: %v", err)
	}

	// Check if our test record is in the list
	found := false
	for _, r := range allRecords {
		if r.RR().Name == "_libdns-test" && r.RR().Type == "TXT" && r.RR().Data == "integration-test-record" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Test record not found in zone after creation")
	} else {
		t.Logf("Verified test record exists in zone")
	}
}

func TestIntegration_SetRecords(t *testing.T) {
	apiToken := os.Getenv("NEODIGIT_TOKEN")
	testDomain := os.Getenv("NEODIGIT_DOMAIN")

	if apiToken == "" || testDomain == "" {
		t.Skip("Skipping integration test - set NEODIGIT_TOKEN and NEODIGIT_DOMAIN to run")
	}

	p := &Provider{
		APIToken: apiToken,
	}

	// Create a test record
	rr := libdns.RR{
		Type: "TXT",
		Name: "_libdns-set-test",
		Data: "initial-value",
		TTL:  300 * time.Second,
	}
	rec, err := rr.Parse()
	if err != nil {
		t.Fatalf("Failed to create test record: %v", err)
	}
	testRecord := []libdns.Record{rec}

	// Clean up any existing test record from previous failed runs
	t.Logf("Cleaning up any existing test records...")
	_, _ = p.DeleteRecords(context.Background(), testDomain, testRecord)

	// Create initial record
	appended, err := p.AppendRecords(context.Background(), testDomain, testRecord)
	if err != nil {
		t.Fatalf("Failed to create initial test record: %v", err)
	}

	// Ensure cleanup happens even if the test fails
	defer func() {
		// Delete using the original record name/type
		deleted, err := p.DeleteRecords(context.Background(), testDomain, testRecord)
		if err != nil {
			t.Errorf("Failed to clean up test record: %v", err)
		} else if len(deleted) > 0 {
			t.Logf("Cleaned up %d test record(s)", len(deleted))
		}
	}()

	if len(appended) != 1 {
		t.Fatalf("Expected 1 appended record, got %d", len(appended))
	}

	t.Logf("Created initial test record")

	// Now update the record with SetRecords
	updatedRR := libdns.RR{
		Type: "TXT",
		Name: "_libdns-set-test",
		Data: "updated-value",
		TTL:  600 * time.Second,
	}
	updatedRec, err := updatedRR.Parse()
	if err != nil {
		t.Fatalf("Failed to create updated record: %v", err)
	}

	setRecords, err := p.SetRecords(context.Background(), testDomain, []libdns.Record{updatedRec})
	if err != nil {
		t.Fatalf("SetRecords() failed: %v", err)
	}

	if len(setRecords) != 1 {
		t.Fatalf("Expected 1 set record, got %d", len(setRecords))
	}

	t.Logf("Successfully updated test record")

	// Verify the record was updated
	allRecords, err := p.GetRecords(context.Background(), testDomain)
	if err != nil {
		t.Errorf("Failed to fetch records for verification: %v", err)
	}

	// Check if our updated record is in the list
	found := false
	for _, r := range allRecords {
		if r.RR().Name == "_libdns-set-test" && r.RR().Type == "TXT" {
			if r.RR().Data == "updated-value" {
				found = true
				t.Logf("Verified test record was updated with new value")
			} else {
				t.Errorf("Test record found but has old value: %s", r.RR().Data)
			}
			break
		}
	}

	if !found {
		t.Errorf("Updated test record not found in zone")
	}
}
