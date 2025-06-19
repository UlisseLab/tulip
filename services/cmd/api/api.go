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
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"tulip/pkg/db"

	"github.com/labstack/echo/v4"
)

// API holds dependencies for handlers
type API struct {
	DB     db.MongoDatabase
	Config *Config
}

// RegisterRoutes registers all API endpoints to the Echo router
func (api *API) RegisterRoutes(e *echo.Echo) {
	e.GET("/", api.helloWorld)
	e.GET("/tick_info", api.getTickInfo)
	e.GET("/tags", api.getTags)
	e.GET("/signature/:id", api.getSignature)
	e.GET("/star/:flow_id/:star_to_set", api.setStar)
	e.GET("/services", api.getServices)
	e.GET("/flag_regex", api.getFlagRegex)
	e.GET("/flow/:id", api.getFlowDetail)
	e.GET("/to_python_request/:id", api.convertToPythonRequests)
	e.GET("/to_pwn/:id", api.convertToPwn)
	e.GET("/download/", api.downloadFile)

	e.POST("/query", api.query)
	e.POST("/to_single_python_request", api.convertToSinglePythonRequest)
}

// --- Handlers ---

func (api *API) helloWorld(c echo.Context) error {
	return c.String(http.StatusOK, "Hello, World!")
}

func (api *API) getTickInfo(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]any{
		"startDate":  api.Config.StartDate,
		"tickLength": api.Config.TickLength,
	})
}

func (api *API) query(c echo.Context) error {

	var filters map[string]any
	if err := c.Bind(&filters); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
	}

	f := make(map[string]any)

	// Handle "flow.data" regex filter
	if v, ok := filters["flow.data"]; ok {
		// MongoDB regex query
		f["flow.data"] = map[string]any{
			"$regex":   v,
			"$options": "i",
		}
	}

	// Handle "dst_ip"
	if v, ok := filters["dst_ip"]; ok {
		f["dst_ip"] = v
	}

	// Handle "dst_port"
	if v, ok := filters["dst_port"]; ok {
		dstPortStr := ""
		switch vv := v.(type) {
		case float64:
			dstPortStr = strconv.Itoa(int(vv))
		case string:
			dstPortStr = vv
		}
		dstPortInt, err := strconv.Atoi(dstPortStr)
		if err == nil {
			if dstPortInt == -1 {
				// Remove dst_ip
				delete(f, "dst_ip")
				// Exclude all service ports
				ninPorts := []int{}
				for _, svc := range api.Config.Services {
					if svc.Port != 0 {
						ninPorts = append(ninPorts, svc.Port)
					}
				}
				f["dst_port"] = map[string]any{
					"$nin": ninPorts,
				}
			} else {
				f["dst_port"] = dstPortInt
			}
		}
	}

	// Handle time range
	fromTime, fromOk := filters["from_time"]
	toTime, toOk := filters["to_time"]
	if fromOk && toOk {
		fromInt := 0
		toInt := 0
		switch v := fromTime.(type) {
		case float64:
			fromInt = int(v)
		case string:
			fromInt, _ = strconv.Atoi(v)
		}
		switch v := toTime.(type) {
		case float64:
			toInt = int(v)
		case string:
			toInt, _ = strconv.Atoi(v)
		}
		f["time"] = map[string]any{
			"$gte": fromInt,
			"$lt":  toInt,
		}
	}

	// Handle tags
	tagQueries := make(map[string]any)
	if v, ok := filters["includeTags"]; ok {
		switch vv := v.(type) {
		case []any:
			strs := []string{}
			for _, elem := range vv {
				strs = append(strs, fmt.Sprintf("%v", elem))
			}
			tagQueries["$all"] = strs
		}
	}
	if v, ok := filters["excludeTags"]; ok {
		switch vv := v.(type) {
		case []any:
			strs := []string{}
			for _, elem := range vv {
				strs = append(strs, fmt.Sprintf("%v", elem))
			}
			tagQueries["$nin"] = strs
		}
	}
	if len(tagQueries) > 0 {
		f["tags"] = tagQueries
	}

	results, err := api.DB.GetFlowList(f)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, results)
}

func (api *API) getTags(c echo.Context) error {
	tags, err := api.DB.GetTagList()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, tags)
}

func (api *API) getSignature(c echo.Context) error {
	id := c.Param("id")
	sig, err := api.DB.GetSignature(id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, sig)
}

func (api *API) setStar(c echo.Context) error {
	flowID := c.Param("flow_id")
	starToSet := c.Param("star_to_set")
	star := starToSet != "0"
	err := api.DB.SetStar(flowID, star)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.String(http.StatusOK, "ok!")
}

func (api *API) getServices(c echo.Context) error {
	return c.JSON(http.StatusOK, api.Config.Services)
}

func (api *API) getFlagRegex(c echo.Context) error {
	return c.JSON(http.StatusOK, api.Config.FlagRegex)
}

func (api *API) getFlowDetail(c echo.Context) error {
	id := c.Param("id")
	flow, err := api.DB.GetFlowDetail(id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
	return c.JSON(http.StatusOK, flow)
}

func (api *API) convertToSinglePythonRequest(c echo.Context) error {
	type Request struct {
		Tokenize   bool   `query:"tokenize"`
		UseSession bool   `query:"use_requests_session"`
		Id         string `query:"id"`
	}

	var req Request
	if err := c.Bind(&req); err != nil {
		return c.String(http.StatusBadRequest, "Invalid request parameters")
	}

	if req.Id == "" {
		return c.String(http.StatusBadRequest, "Query parameter 'id' is required")
	}

	flow, err := api.DB.GetFlowDetail(req.Id)
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

func (api *API) convertToPythonRequests(c echo.Context) error {
	id := c.Param("id")
	tokenize, _ := strconv.ParseBool(c.QueryParam("tokenize"))
	useSession, _ := strconv.ParseBool(c.QueryParam("use_requests_session"))

	flow, err := api.DB.GetFlowDetail(id)
	if err != nil || flow == nil {
		return c.String(http.StatusBadRequest, "There was an error while converting the request:\nInvalid flow: Invalid flow id")
	}

	py, err := convertFlowToHTTPRequests(flow, tokenize, useSession)
	if err != nil {
		return c.String(http.StatusInternalServerError, fmt.Sprintf("There was an error while converting the request:\n%s: %s", err.Error(), err))
	}
	return c.String(http.StatusOK, py)
}

func (api *API) convertToPwn(c echo.Context) error {
	id := c.Param("id")
	flow, err := api.DB.GetFlowDetail(id)
	if err != nil || flow == nil {
		return c.String(http.StatusBadRequest, "There was an error while converting the request:\nInvalid flow: Invalid flow id")
	}
	script := flowToPwn(flow)
	return c.String(http.StatusOK, script)
}

func (api *API) downloadFile(c echo.Context) error {
	fileParam := c.QueryParam("file")
	if fileParam == "" {
		return c.String(http.StatusBadRequest, "There was an error while downloading the requested file:\nInvalid 'file': No 'file' given")
	}

	absPath, err := filepath.Abs(fileParam)
	if err != nil {
		return c.String(http.StatusBadRequest, "There was an error while downloading the requested file:\nInvalid 'file': Could not resolve path")
	}

	trafficDir := api.Config.TrafficDir
	trafficDirAbs, err := filepath.Abs(trafficDir)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal error: could not resolve traffic_dir")
	}

	// Ensure requested file is within trafficDir
	if !isSubPath(absPath, trafficDirAbs) {
		return c.String(http.StatusBadRequest, "There was an error while downloading the requested file:\nInvalid 'file': 'file' was not in a subdirectory of traffic_dir")
	}

	f, err := os.Open(absPath)
	if err != nil {
		return c.String(http.StatusNotFound, "There was an error while downloading the requested file:\nInvalid 'file': 'file' not found")
	}
	defer f.Close()

	c.Response().Header().Set("Content-Disposition", "attachment; filename="+filepath.Base(absPath))
	c.Response().Header().Set("Content-Type", "application/octet-stream")
	_, _ = io.Copy(c.Response().Writer, f)
	return nil
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
		if msg.From == "c" {
			req, data, dataParam, headers, err := decodeHTTPRequest([]byte(msg.Data), tokenize)
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
		data, _ := base64.StdEncoding.DecodeString(msg.B64)
		if msg.From == "c" {
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
