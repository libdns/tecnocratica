package tecnocratica

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestNewClient(t *testing.T) {
	tests := []struct {
		name    string
		apiURL  string
		wantErr bool
	}{
		{
			name:    "default URL",
			apiURL:  "",
			wantErr: false,
		},
		{
			name:    "custom URL",
			apiURL:  "https://custom.api.example.com/v1",
			wantErr: false,
		},
		{
			name:    "invalid URL",
			apiURL:  "://invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Provider{
				APIToken: "test-token",
				APIURL:   tt.apiURL,
			}

			client, err := newClient(p)
			if (err != nil) != tt.wantErr {
				t.Errorf("newClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if client == nil {
					t.Error("newClient() returned nil client")
					return
				}
				if client.token != "test-token" {
					t.Errorf("newClient() token = %v, want %v", client.token, "test-token")
				}
				expectedURL := tt.apiURL
				if expectedURL == "" {
					expectedURL = DefaultBaseURL
				}
				if client.BaseURL.String() != expectedURL {
					t.Errorf("newClient() BaseURL = %v, want %v", client.BaseURL.String(), expectedURL)
				}
			}
		})
	}
}

func TestClient_GetZones(t *testing.T) {
	tests := []struct {
		name           string
		responseStatus int
		responseBody   interface{}
		wantErr        bool
		wantZoneCount  int
	}{
		{
			name:           "successful response",
			responseStatus: http.StatusOK,
			responseBody: []Zone{
				{ID: 1, Name: "example.com"},
				{ID: 2, Name: "example.org"},
			},
			wantErr:       false,
			wantZoneCount: 2,
		},
		{
			name:           "empty zones",
			responseStatus: http.StatusOK,
			responseBody:   []Zone{},
			wantErr:        false,
			wantZoneCount:  0,
		},
		{
			name:           "server error",
			responseStatus: http.StatusInternalServerError,
			responseBody:   map[string]string{"error": "internal server error"},
			wantErr:        true,
		},
		{
			name:           "unauthorized",
			responseStatus: http.StatusUnauthorized,
			responseBody:   map[string]string{"error": "unauthorized"},
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check method
				if r.Method != http.MethodGet {
					t.Errorf("Expected GET request, got %s", r.Method)
				}

				// Check path
				if r.URL.Path != "/dns/zones" {
					t.Errorf("Expected path /dns/zones, got %s", r.URL.Path)
				}

				// Check authentication header
				if r.Header.Get("X-TCpanel-Token") != "test-token" {
					t.Errorf("Expected X-TCpanel-Token header, got %s", r.Header.Get("X-TCpanel-Token"))
				}

				w.WriteHeader(tt.responseStatus)
				json.NewEncoder(w).Encode(tt.responseBody)
			}))
			defer server.Close()

			baseURL, _ := url.Parse(server.URL)
			client := &Client{
				token:      "test-token",
				BaseURL:    baseURL,
				HTTPClient: server.Client(),
			}

			zones, err := client.getZones(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("getZones() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(zones) != tt.wantZoneCount {
				t.Errorf("getZones() returned %d zones, want %d", len(zones), tt.wantZoneCount)
			}
		})
	}
}

func TestClient_GetRecords(t *testing.T) {
	tests := []struct {
		name            string
		zoneID          int
		recordType      string
		responseStatus  int
		responseBody    interface{}
		wantErr         bool
		wantRecordCount int
		checkQuery      bool
	}{
		{
			name:           "all records",
			zoneID:         1,
			recordType:     "",
			responseStatus: http.StatusOK,
			responseBody: []Record{
				{ID: 1, Name: "www", Type: "A", Content: "192.0.2.1", TTL: 3600},
				{ID: 2, Name: "mail", Type: "A", Content: "192.0.2.2", TTL: 3600},
			},
			wantErr:         false,
			wantRecordCount: 2,
		},
		{
			name:           "filtered by type",
			zoneID:         1,
			recordType:     "A",
			responseStatus: http.StatusOK,
			responseBody: []Record{
				{ID: 1, Name: "www", Type: "A", Content: "192.0.2.1", TTL: 3600},
			},
			wantErr:         false,
			wantRecordCount: 1,
			checkQuery:      true,
		},
		{
			name:           "zone not found",
			zoneID:         999,
			recordType:     "",
			responseStatus: http.StatusNotFound,
			responseBody:   map[string]string{"error": "zone not found"},
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("Expected GET request, got %s", r.Method)
				}

				if tt.checkQuery && tt.recordType != "" {
					if r.URL.Query().Get("type") != tt.recordType {
						t.Errorf("Expected type query param %s, got %s", tt.recordType, r.URL.Query().Get("type"))
					}
				}

				w.WriteHeader(tt.responseStatus)
				json.NewEncoder(w).Encode(tt.responseBody)
			}))
			defer server.Close()

			baseURL, _ := url.Parse(server.URL)
			client := &Client{
				token:      "test-token",
				BaseURL:    baseURL,
				HTTPClient: server.Client(),
			}

			records, err := client.getRecords(context.Background(), tt.zoneID, tt.recordType)
			if (err != nil) != tt.wantErr {
				t.Errorf("getRecords() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(records) != tt.wantRecordCount {
				t.Errorf("getRecords() returned %d records, want %d", len(records), tt.wantRecordCount)
			}
		})
	}
}

func TestClient_CreateRecord(t *testing.T) {
	tests := []struct {
		name           string
		zoneID         int
		record         Record
		responseStatus int
		responseBody   interface{}
		wantErr        bool
	}{
		{
			name:   "successful creation",
			zoneID: 1,
			record: Record{
				Name:    "test",
				Type:    "A",
				Content: "192.0.2.1",
				TTL:     3600,
			},
			responseStatus: http.StatusCreated,
			responseBody: Record{
				ID:      123,
				Name:    "test",
				Type:    "A",
				Content: "192.0.2.1",
				TTL:     3600,
			},
			wantErr: false,
		},
		{
			name:   "validation error",
			zoneID: 1,
			record: Record{
				Name:    "invalid..name",
				Type:    "A",
				Content: "not-an-ip",
				TTL:     3600,
			},
			responseStatus: http.StatusBadRequest,
			responseBody:   map[string]string{"error": "validation failed"},
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("Expected POST request, got %s", r.Method)
				}

				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
				}

				w.WriteHeader(tt.responseStatus)
				json.NewEncoder(w).Encode(tt.responseBody)
			}))
			defer server.Close()

			baseURL, _ := url.Parse(server.URL)
			client := &Client{
				token:      "test-token",
				BaseURL:    baseURL,
				HTTPClient: server.Client(),
			}

			record, err := client.createRecord(context.Background(), tt.zoneID, tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("createRecord() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && record == nil {
				t.Error("createRecord() returned nil record")
			}
		})
	}
}

func TestClient_DeleteRecord(t *testing.T) {
	tests := []struct {
		name           string
		zoneID         int
		recordID       int
		responseStatus int
		wantErr        bool
	}{
		{
			name:           "successful deletion",
			zoneID:         1,
			recordID:       123,
			responseStatus: http.StatusNoContent,
			wantErr:        false,
		},
		{
			name:           "record not found",
			zoneID:         1,
			recordID:       999,
			responseStatus: http.StatusNotFound,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("Expected DELETE request, got %s", r.Method)
				}

				w.WriteHeader(tt.responseStatus)
			}))
			defer server.Close()

			baseURL, _ := url.Parse(server.URL)
			client := &Client{
				token:      "test-token",
				BaseURL:    baseURL,
				HTTPClient: server.Client(),
			}

			err := client.deleteRecord(context.Background(), tt.zoneID, tt.recordID)
			if (err != nil) != tt.wantErr {
				t.Errorf("deleteRecord() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDoJSONRequest(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		payload interface{}
		wantErr bool
	}{
		{
			name:    "GET without payload",
			method:  http.MethodGet,
			payload: nil,
			wantErr: false,
		},
		{
			name:   "POST with payload",
			method: http.MethodPost,
			payload: map[string]string{
				"key": "value",
			},
			wantErr: false,
		},
		{
			name:   "PUT with payload",
			method: http.MethodPut,
			payload: Record{
				Name:    "test",
				Type:    "A",
				Content: "192.0.2.1",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testURL, _ := url.Parse("https://api.example.com/test")
			req, err := doJSONRequest(context.Background(), tt.method, testURL, tt.payload)

			if (err != nil) != tt.wantErr {
				t.Errorf("doJSONRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if req == nil {
					t.Error("doJSONRequest() returned nil request")
					return
				}

				if req.Method != tt.method {
					t.Errorf("Expected method %s, got %s", tt.method, req.Method)
				}

				if req.Header.Get("User-Agent") != userAgent {
					t.Errorf("Expected User-Agent %s, got %s", userAgent, req.Header.Get("User-Agent"))
				}

				if req.Header.Get("Accept") != "application/json" {
					t.Errorf("Expected Accept application/json, got %s", req.Header.Get("Accept"))
				}

				if tt.payload != nil && req.Header.Get("Content-Type") != "application/json" {
					t.Errorf("Expected Content-Type application/json, got %s", req.Header.Get("Content-Type"))
				}
			}
		})
	}
}
