// SPDX-FileCopyrightText: 2026 Eyad Issa <eyadlorenzo@gmail.com>
//
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"tulip/pkg/db"
)

// mockDB records the FindFlowsOptions passed to GetFlows for inspection.
type mockDB struct {
	lastOpts *db.FindFlowsOptions
}

func (m *mockDB) GetFlows(ctx context.Context, opts *db.FindFlowsOptions) ([]db.FlowEntry, error) {
	m.lastOpts = opts
	return []db.FlowEntry{}, nil
}
func (m *mockDB) GetSignaturesBatch(ctx context.Context, ids []string) ([]db.SuricataSig, error) {
	return nil, nil
}
func (m *mockDB) InsertFlows(context.Context, []db.FlowEntry) error            { return nil }
func (m *mockDB) CountFlows(context.Context, bson.D) (int64, error)            { return 0, nil }
func (m *mockDB) CountFlowsByOpts(context.Context, *db.FindFlowsOptions) (int64, error) {
	return 0, nil
}
func (m *mockDB) SetStar(context.Context, string, bool) error                  { return nil }
func (m *mockDB) GetFlowDetail(context.Context, string) (*db.FlowEntry, error) { return nil, nil }
func (m *mockDB) GetTagList(context.Context) ([]string, error)                 { return nil, nil }
func (m *mockDB) GetSignature(context.Context, string) (db.SuricataSig, error) {
	return db.SuricataSig{}, nil
}
func (m *mockDB) GetPcap(context.Context, string) (bool, db.PcapFile) { return false, db.PcapFile{} }
func (m *mockDB) InsertPcap(context.Context, db.PcapFile) error       { return nil }
func (m *mockDB) ConfigureDatabase() error                            { return nil }
func (m *mockDB) AddSignatureToFlow(context.Context, db.FlowID, db.SuricataSig, int) error {
	return nil
}
func (m *mockDB) InsertTags(context.Context, []string) error                    { return nil }
func (m *mockDB) AddTagsToFlow(context.Context, db.FlowID, []string, int) error { return nil }
func (m *mockDB) GetFingerprints(context.Context) ([]int, error)                { return nil, nil }

func newTestRouter(mdb db.Database) *Router {
	return &Router{
		DB:     mdb,
		Config: &Config{},
	}
}

func doQuery(t *testing.T, router *Router, body string) *httptest.ResponseRecorder {
	t.Helper()
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/query", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	err := router.query(c)
	require.NoError(t, err)
	return rec
}

// TestQueryEmptyTagsNoFilter verifies that sending empty includeTags/excludeTags
// does not add a tag filter — all flows should be returned regardless of tags.
func TestQueryEmptyTagsNoFilter(t *testing.T) {
	mdb := &mockDB{}
	router := newTestRouter(mdb)

	rec := doQuery(t, router, `{"includeTags":[],"excludeTags":[]}`)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, mdb.lastOpts)
	assert.Empty(t, mdb.lastOpts.IncludeTags, "empty includeTags should not be forwarded as a filter")
	assert.Empty(t, mdb.lastOpts.ExcludeTags, "empty excludeTags should not be forwarded as a filter")
}

// TestQueryIncludeTagsForwarded verifies that non-empty includeTags are passed through.
func TestQueryIncludeTagsForwarded(t *testing.T) {
	mdb := &mockDB{}
	router := newTestRouter(mdb)

	rec := doQuery(t, router, `{"includeTags":["flag-in","http"]}`)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, mdb.lastOpts)
	assert.Equal(t, []string{"flag-in", "http"}, mdb.lastOpts.IncludeTags)
}

// TestQueryExcludeTagsForwarded verifies that non-empty excludeTags are passed through.
func TestQueryExcludeTagsForwarded(t *testing.T) {
	mdb := &mockDB{}
	router := newTestRouter(mdb)

	rec := doQuery(t, router, `{"excludeTags":["starred"]}`)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, mdb.lastOpts)
	assert.Equal(t, []string{"starred"}, mdb.lastOpts.ExcludeTags)
}

// TestQueryResponseIsJSON verifies that /query returns a paginated JSON envelope.
func TestQueryResponseIsJSON(t *testing.T) {
	mdb := &mockDB{}
	router := newTestRouter(mdb)

	rec := doQuery(t, router, `{}`)

	assert.Equal(t, http.StatusOK, rec.Code)
	var result struct {
		Data         []json.RawMessage `json:"data"`
		Page         int               `json:"page"`
		Count        int64             `json:"count"`
		ItemsPerPage int               `json:"items_per_page"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
}

// TestQueryDefaultLimit verifies that when no limit is provided the default (50) is applied.
func TestQueryDefaultLimit(t *testing.T) {
	mdb := &mockDB{}
	router := newTestRouter(mdb)

	doQuery(t, router, `{}`)

	require.NotNil(t, mdb.lastOpts)
	assert.Equal(t, 50, mdb.lastOpts.Limit)
}

// Satisfy unused imports from primitive (used indirectly via db types in test helpers).
var _ = primitive.NilObjectID
