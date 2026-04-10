// SPDX-FileCopyrightText: 2025 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"tulip/pkg/db"

	"github.com/labstack/echo/v4"
)

// Router holds dependencies for handlers
type Router struct {
	DB     db.Database
	Config *Config
}

// RegisterRoutes registers all API endpoints to the Echo router
func (api *Router) RegisterRoutes(e *echo.Echo) {
	e.GET("/", api.helloWorld)
	e.GET("/tick_info", api.getTickInfo)
	e.GET("/tags", api.getTags)
	e.GET("/signature/:id", api.getSignature)
	e.PATCH("/star/:flow_id/:star_to_set", api.setStar)
	e.GET("/services", api.getServices)
	e.GET("/flag_regex", api.getFlagRegex)
	e.GET("/flow/:id", api.getFlowDetail)
	e.GET("/to_python_request/:id", api.convertToPythonRequests)
	e.GET("/to_pwn/:id", api.convertToPwn)
	e.GET("/download/", api.downloadFile)
	e.GET("/fingerprints", api.getFingerprints)

	e.POST("/query", api.query)
	e.POST("/to_single_python_request", api.convertToSinglePythonRequest)
}

type apiError struct {
	Error string `json:"error"`
}

// --- Handlers ---

func (api *Router) helloWorld(c echo.Context) error {
	return c.String(http.StatusOK, "Hello, World!")
}

func (api *Router) getTickInfo(c echo.Context) error {
	type tickInfo struct {
		StartDate  string `json:"startDate"`  // Start date of the tick
		TickLength int    `json:"tickLength"` // Length of each tick in seconds
	}

	info := tickInfo{StartDate: api.Config.StartDate, TickLength: api.Config.TickLength}
	return c.JSON(http.StatusOK, info)
}

func (api *Router) query(c echo.Context) error {

	type flowQueryRequest struct {
		IncludeTags  []string `json:"includeTags"`
		ExcludeTags  []string `json:"excludeTags"`
		FlowData     string   `json:"flow.data"`
		DstIp        string   `json:"dst_ip"`
		DstPort      int      `json:"dst_port"`
		FromTime     int64    `json:"from_time"`
		ToTime       int64    `json:"to_time"`
		FlagIds      []string `json:"flagids"`
		Flags        []string `json:"flags"`
		Service      string   `json:"service"`
		Limit        int      `json:"limit"`
		Offset       int      `json:"offset"`
		Fingerprints []int    `json:"fingerprints"` // Fingerprints to filter by
	}

	var req flowQueryRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, apiError{Error: "Invalid request format"})
	}

	opts := &db.FindFlowsOptions{
		FromTime:     req.FromTime,
		ToTime:       req.ToTime,
		IncludeTags:  req.IncludeTags,
		ExcludeTags:  req.ExcludeTags,
		DstIp:        req.DstIp,
		FlowData:     req.FlowData,
		Limit:        req.Limit,
		Offset:       req.Offset,
		Fingerprints: req.Fingerprints,
	}

	if opts.Limit <= 0 {
		opts.Limit = 50
	}

	// DstPort == -1 means "exclude all known service ports" (show non-service traffic)
	if req.DstPort == -1 {
		excludePorts := make([]int, 0, len(api.Config.Services))
		for _, svc := range api.Config.Services {
			if svc.Port != 0 {
				excludePorts = append(excludePorts, svc.Port)
			}
		}
		opts.ExcludePorts = excludePorts
	} else if req.DstPort != 0 {
		opts.DstPort = req.DstPort
	}

	type apiFlowEntry struct {
		db.FlowEntry
		Signatures []db.SuricataSig `json:"signatures"` // Signatures matched by this flow
	}

	slog.Info("Querying flows", slog.Any("options", opts))

	results, err := api.DB.GetFlows(c.Request().Context(), opts)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}

	// Count total matching flows in parallel with signature fetching.
	var totalCount int64
	var countErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		totalCount, countErr = api.DB.CountFlowsByOpts(c.Request().Context(), opts)
	}()

	// Collect all unique signature IDs across all flows for a single batch query.
	allSigIDs := make([]string, 0)
	sigIDSeen := make(map[string]bool)
	for _, flow := range results {
		for _, sigID := range flow.Suricata {
			if !sigIDSeen[sigID] {
				sigIDSeen[sigID] = true
				allSigIDs = append(allSigIDs, sigID)
			}
		}
	}
	sigMap := make(map[string]db.SuricataSig, len(allSigIDs))
	if len(allSigIDs) > 0 {
		sigs, err := api.DB.GetSignaturesBatch(c.Request().Context(), allSigIDs)
		if err != nil {
			slog.Error("Failed to fetch signatures", slog.Any("err", err))
			return c.JSON(http.StatusInternalServerError,
				apiError{"Could not fetch signatures. See server logs for details."})
		}
		for _, sig := range sigs {
			sigMap[sig.MongoID.Hex()] = sig
		}
	}

	apiResults := make([]apiFlowEntry, len(results))
	for i, flow := range results {
		res := apiFlowEntry{FlowEntry: flow}

		res.Signatures = make([]db.SuricataSig, 0, len(flow.Suricata))
		for _, sigID := range flow.Suricata {
			if sig, ok := sigMap[sigID]; ok {
				res.Signatures = append(res.Signatures, sig)
			}
		}

		apiResults[i] = res
	}

	wg.Wait()
	if countErr != nil {
		slog.Error("Failed to count flows", slog.Any("err", countErr))
		return c.JSON(http.StatusInternalServerError, apiError{"Could not count flows. See server logs for details."})
	}

	page := 1
	if opts.Limit > 0 {
		page = opts.Offset/opts.Limit + 1
	}

	return c.JSON(http.StatusOK, map[string]any{
		"data":           apiResults,
		"page":           page,
		"count":          totalCount,
		"items_per_page": opts.Limit,
	})
}

func (api *Router) getTags(c echo.Context) error {
	tags, err := api.DB.GetTagList(c.Request().Context())
	if err != nil {
		slog.Error("Failed to fetch tags", slog.Any("err", err))
		return c.JSON(http.StatusInternalServerError, apiError{"Could not fetch tags. See server logs for details."})
	}
	return c.JSON(http.StatusOK, tags)
}

func (api *Router) getSignature(c echo.Context) error {
	id := c.Param("id")
	sig, err := api.DB.GetSignature(c.Request().Context(), id)
	if err != nil {
		slog.Error("Failed to fetch signature", slog.String("id", id), slog.Any("err", err))
		return c.JSON(http.StatusInternalServerError, apiError{"Could not fetch signature. See server logs for details."})
	}
	return c.JSON(http.StatusOK, sig)
}

func (api *Router) setStar(c echo.Context) error {
	flowID := c.Param("flow_id")
	starToSet := c.Param("star_to_set")
	star := starToSet != "0"
	err := api.DB.SetStar(c.Request().Context(), flowID, star)
	if err != nil {
		slog.Error("Failed to set star", slog.String("flow_id", flowID), slog.Any("err", err))
		return c.JSON(http.StatusInternalServerError, apiError{"Could not set star. See server logs for details."})
	}
	return c.String(http.StatusOK, "ok!")
}

func (api *Router) getServices(c echo.Context) error {

	type apiService struct {
		Name string `json:"name"`
		Port int    `json:"port"`
		Ip   string `json:"ip"`
	}

	// Convert Config.Services to apiService format
	services := make([]apiService, len(api.Config.Services))
	for i, svc := range api.Config.Services {
		services[i] = apiService{Name: svc.Name, Port: svc.Port, Ip: api.Config.VMIP}
	}

	return c.JSON(http.StatusOK, services)
}

func (api *Router) getFlagRegex(c echo.Context) error {
	return c.JSON(http.StatusOK, api.Config.FlagRegex)
}

func (api *Router) getFlowDetail(c echo.Context) error {
	id := c.Param("id")

	flow, err := api.DB.GetFlowDetail(c.Request().Context(), id)
	if err != nil {
		slog.Error("Failed to fetch flow detail", slog.String("id", id), slog.Any("err", err))
		return c.JSON(http.StatusInternalServerError, apiError{"Could not fetch flow detail. See server logs for details."})
	}

	return c.JSON(http.StatusOK, flow)
}

func (api *Router) convertToSinglePythonRequest(c echo.Context) error {
	type request struct {
		Id         string `query:"id"`
		Tokenize   bool   `query:"tokenize"`
		UseSession bool   `query:"use_requests_session,omitempty"`
	}

	var req request
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "Invalid request format")
	}

	flow, err := api.DB.GetFlowDetail(c.Request().Context(), req.Id)
	if err != nil || flow == nil {
		return c.String(http.StatusBadRequest, "Invalid flow id")
	}

	body, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return c.String(http.StatusBadRequest, "Could not read request body")
	}
	raw, err := base64.StdEncoding.DecodeString(string(body))
	if err != nil {
		return c.String(http.StatusBadRequest, "Could not decode base64 request body")
	}

	py, err := convertSingleHTTPRequest(raw, flow, req.Tokenize, req.UseSession)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("There was an error while converting the request:\n%s: %s", err.Error(), err))
	}
	return c.String(http.StatusOK, py)
}

func (api *Router) convertToPythonRequests(c echo.Context) error {
	id := c.Param("id")
	tokenize, _ := strconv.ParseBool(c.QueryParam("tokenize"))
	useSession, _ := strconv.ParseBool(c.QueryParam("use_requests_session"))

	flow, err := api.DB.GetFlowDetail(c.Request().Context(), id)
	if err != nil || flow == nil {
		return c.String(http.StatusBadRequest, "Invalid flow: Invalid flow id")
	}

	py, err := convertFlowToHTTPRequests(flow, tokenize, useSession)
	if err != nil {
		slog.Error("Failed to convert flow to Python requests", slog.String("id", id), slog.Any("err", err))
		return c.JSON(http.StatusInternalServerError, apiError{"Could not convert flow to Python requests. See server logs for details."})
	}
	return c.String(http.StatusOK, py)
}

func (api *Router) convertToPwn(c echo.Context) error {
	id := c.Param("id")
	flow, err := api.DB.GetFlowDetail(c.Request().Context(), id)
	if err != nil || flow == nil {
		return c.String(http.StatusBadRequest, "Invalid flow: Invalid flow id")
	}
	script := flowToPwn(flow)
	return c.String(http.StatusOK, script)
}

func (api *Router) downloadFile(c echo.Context) error {
	fileParam := c.QueryParam("file")
	if fileParam == "" {
		return c.String(http.StatusBadRequest, "Invalid 'file': No 'file' given")
	}

	// Resolve the absolute path of the requested file
	absPath, err := filepath.Abs(fileParam)
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid 'file': Could not resolve path")
	}

	//
	trafficDir := api.Config.TrafficDir
	trafficDirAbs, err := filepath.Abs(trafficDir)
	if err != nil {
		return c.String(http.StatusInternalServerError,
			"Internal error: could not resolve traffic_dir. Contact the administrator.")
	}

	// Ensure requested file is within trafficDir
	if !isSubPath(absPath, trafficDirAbs) {
		return c.String(http.StatusBadRequest, "Invalid 'file': 'file' was not in a subdirectory of traffic_dir")
	}

	// Check if the file exists
	_, err = os.Stat(absPath)
	if err != nil {
		return c.String(http.StatusNotFound, "Invalid 'file': 'file' not found")
	}

	return c.File(absPath) // This will write the file to the response
}

func (a *Router) getFingerprints(c echo.Context) error {
	res, err := a.DB.GetFingerprints(c.Request().Context())
	if err != nil {
		slog.Error("Failed to fetch fingerprints", slog.Any("err", err))
		return c.JSON(http.StatusInternalServerError, apiError{"Could not fetch fingerprints. See server logs for details."})
	}

	return c.JSON(http.StatusOK, res)
}

// --- Helpers ---

// --- Python HTTP request conversion helpers ---

// convertSingleHTTPRequest generates Python code for a single HTTP request
func convertSingleHTTPRequest(raw []byte, flow *db.FlowEntry, tokenize, useSession bool) (string, error) {
	req, data, dataParam, headers, err := decodeHTTPRequest(raw, tokenize)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(req.Path, "/") {
		return "", fmt.Errorf("request path must start with / to be a valid HTTP request")
	}
	requestMethod, err := validateRequestMethod(req.Method)
	if err != nil {
		return "", err
	}
	py := renderPythonRequest(headers, data, requestMethod, req.Path, dataParam, useSession, flow.DstPort)
	return py, nil
}

// convertFlowToHTTPRequests generates Python code for all HTTP requests in a flow
func convertFlowToHTTPRequests(flow *db.FlowEntry, tokenize, useSession bool) (string, error) {
	var b strings.Builder
	b.WriteString("import os\nimport requests\nimport sys\n\nhost = sys.argv[1]\n")
	if useSession {
		b.WriteString("s = requests.Session()\n")
	}
	for _, msg := range flow.Flow {
		if msg.From == db.FlowItemFromClient {
			req, data, dataParam, headers, err := decodeHTTPRequest(msg.Raw, tokenize)
			if err != nil {
				return "", err
			}
			requestMethod, err := validateRequestMethod(req.Method)
			if err != nil {
				return "", err
			}
			b.WriteString(renderPythonRequest(headers, data, requestMethod, req.Path, dataParam, useSession, flow.DstPort))
			b.WriteString("\n")
		}
	}
	return b.String(), nil
}

// decodeHTTPRequest parses a raw HTTP request (as bytes) into method, path, headers, and body
type parsedRequest struct {
	Method string
	Path   string
	Body   []byte
}

func decodeHTTPRequest(raw []byte, tokenize bool) (parsedRequest, any, string, map[string]string, error) {
	// Very basic HTTP request parsing for demonstration
	lines := bytes.SplitN(raw, []byte("\r\n\r\n"), 2)
	if len(lines) < 1 {
		return parsedRequest{}, nil, "", nil, fmt.Errorf("invalid HTTP request")
	}
	headerLines := bytes.Split(lines[0], []byte("\r\n"))
	if len(headerLines) < 1 {
		return parsedRequest{}, nil, "", nil, fmt.Errorf("invalid HTTP request")
	}
	requestLine := strings.Fields(string(headerLines[0]))
	if len(requestLine) < 2 {
		return parsedRequest{}, nil, "", nil, fmt.Errorf("invalid HTTP request line")
	}
	method := requestLine[0]
	path := requestLine[1]
	headers := make(map[string]string)
	for _, h := range headerLines[1:] {
		parts := strings.SplitN(string(h), ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	body := []byte{}
	if len(lines) > 1 {
		body = lines[1]
	}
	// For simplicity, just return the body as-is
	data := body
	dataParam := "data"
	contentType := headers["Content-Type"]
	if tokenize && len(body) > 0 {
		if strings.HasPrefix(contentType, "application/json") {
			dataParam = "json"
			var jsonObj any
			_ = json.Unmarshal(body, &jsonObj)
			// Marshal back to []byte for consistent handling
			dataBytes, _ := json.Marshal(jsonObj)
			data = dataBytes
		}
	}
	return parsedRequest{Method: method, Path: path, Body: body}, data, dataParam, headers, nil
}

func validateRequestMethod(method string) (string, error) {
	m := strings.ToLower(method)
	switch m {
	case "delete", "get", "head", "options", "patch", "post", "put":
		return m, nil
	default:
		return "", fmt.Errorf("invalid request method: %s", method)
	}
}

func renderPythonRequest(headers map[string]string, data any, method, path, dataParam string, useSession bool, port int) string {
	var b strings.Builder
	b.WriteString("\n")
	if useSession {
		b.WriteString("s.headers = ")
	} else {
		b.WriteString("headers = ")
	}
	headersJson, _ := json.Marshal(headers)
	b.WriteString(string(headersJson))
	b.WriteString("\n")
	b.WriteString("data = ")
	dataJson, _ := json.Marshal(data)
	b.WriteString(string(dataJson))
	b.WriteString("\n")
	if useSession {
		b.WriteString(fmt.Sprintf("s.%s(f\"http://{{host}}:%d%s\", %s=data)\n", method, port, path, dataParam))
	} else {
		b.WriteString(fmt.Sprintf("requests.%s(f\"http://{{host}}:%d%s\", %s=data, headers=headers)\n", method, port, path, dataParam))
	}
	return b.String()
}

// --- Pwn script conversion helper ---

func flowToPwn(flow *db.FlowEntry) string {
	var b strings.Builder
	b.WriteString("from pwn import *\nimport sys\n\nhost = sys.argv[1]\n")
	b.WriteString(fmt.Sprintf("proc = remote(host, %d)\n", flow.DstPort))
	for _, msg := range flow.Flow {
		data := msg.Raw
		if msg.From == db.FlowItemFromClient {
			b.WriteString(fmt.Sprintf("proc.write(b\"%s\")\n", escapeBytes(data)))
		} else {
			// Show last 10 bytes for server messages
			suffix := data
			if len(data) > 10 {
				suffix = data[len(data)-10:]
			}
			b.WriteString(fmt.Sprintf("proc.recvuntil(b\"%s\")\n", escapeBytes(suffix)))
		}
	}
	return b.String()
}

func escapeBytes(data []byte) string {
	var b strings.Builder
	for _, i := range data {
		if i >= 0x20 && i < 0x7f {
			if i == '\\' || i == '"' {
				b.WriteByte('\\')
			}
			b.WriteByte(i)
		} else {
			b.WriteString(fmt.Sprintf("\\x%02x", i))
		}
	}
	return b.String()
}

// isSubPath returns true if sub is a subdirectory (or file within) base
func isSubPath(sub, base string) bool {
	rel, err := filepath.Rel(base, sub)
	if err != nil {
		return false
	}
	return rel == "." || (len(rel) > 0 && rel[0] != '.')
}
