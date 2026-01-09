package tecnocratica

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	userAgent      = "tecnocratica-libdns/1.0"
	DefaultBaseURL = "https://api.neodigit.net/v1"
)

// Client is a Neodigit API client.
type Client struct {
	token      string
	BaseURL    *url.URL
	HTTPClient *http.Client
}

// NewClient creates a new Client.
func newClient(p *Provider) (*Client, error) {
	baseURL := p.APIURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid API URL: %w", err)
	}

	return &Client{
		token:      p.APIToken,
		BaseURL:    parsedURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// GetZones lists all DNS zones.
func (c *Client) getZones(ctx context.Context) ([]Zone, error) {
	endpoint := c.BaseURL.JoinPath("dns", "zones")

	req, err := doJSONRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var zones []Zone

	err = c.do(req, &zones)
	if err != nil {
		return nil, err
	}

	return zones, nil
}

// GetRecords lists all records in a zone.
func (c *Client) getRecords(ctx context.Context, zoneID int, recordType string) ([]Record, error) {
	endpoint := c.BaseURL.JoinPath("dns", "zones", strconv.Itoa(zoneID), "records")

	if recordType != "" {
		query := endpoint.Query()
		query.Set("type", recordType)
		endpoint.RawQuery = query.Encode()
	}

	req, err := doJSONRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	var records []Record

	err = c.do(req, &records)
	if err != nil {
		return nil, err
	}

	return records, nil
}

// CreateRecord creates a new DNS record.
func (c *Client) createRecord(ctx context.Context, zoneID int, record Record) (*Record, error) {
	endpoint := c.BaseURL.JoinPath("dns", "zones", strconv.Itoa(zoneID), "records")

	payload := RecordRequest{Record: record}

	req, err := doJSONRequest(ctx, http.MethodPost, endpoint, payload)
	if err != nil {
		return nil, err
	}

	var result Record

	err = c.do(req, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// UpdateRecord updates an existing DNS record.
func (c *Client) updateRecord(ctx context.Context, zoneID, recordID int, record Record) (*Record, error) {
	endpoint := c.BaseURL.JoinPath("dns", "zones", strconv.Itoa(zoneID), "records", strconv.Itoa(recordID))

	payload := RecordRequest{Record: record}

	req, err := doJSONRequest(ctx, http.MethodPut, endpoint, payload)
	if err != nil {
		return nil, err
	}

	var result Record

	err = c.do(req, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// DeleteRecord deletes a DNS record.
func (c *Client) deleteRecord(ctx context.Context, zoneID, recordID int) error {
	endpoint := c.BaseURL.JoinPath("dns", "zones", strconv.Itoa(zoneID), "records", strconv.Itoa(recordID))

	req, err := doJSONRequest(ctx, http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}

	return c.do(req, nil)
}

func (c *Client) do(req *http.Request, result any) error {
	req.Header.Set("X-TCpanel-Token", c.token)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("unexpected http error: request: %v, error: %w", req.URL, err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("unexpected status code: %d, request: %v, response: %s", resp.StatusCode, req.URL, raw)
	}

	if result == nil {
		return nil
	}

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response: status: %d, request: %v, error: %w", resp.StatusCode, req.URL, err)
	}

	err = json.Unmarshal(raw, result)
	if err != nil {
		return fmt.Errorf("error unmarshaling response: status: %d, request: %v, response: %s, error: %w", resp.StatusCode, req.URL, raw, err)
	}

	return nil
}

func doJSONRequest(ctx context.Context, method string, endpoint *url.URL, payload any) (*http.Request, error) {
	body := new(bytes.Buffer)

	if payload != nil {
		err := json.NewEncoder(body).Encode(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to create request JSON body: %w", err)
		}
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %w", err)
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return req, nil
}
