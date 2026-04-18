package fetch

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dvstc/ipguard/tgeo"
)

func buildTestTGEOGzip(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.Write([]byte("TGEO"))
	binary.Write(&buf, binary.BigEndian, uint32(1)) // version
	binary.Write(&buf, binary.BigEndian, uint32(2)) // 2 entries
	binary.Write(&buf, binary.BigEndian, uint32(0x01000000))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint32(0x02000000))
	binary.Write(&buf, binary.BigEndian, uint16(1))
	binary.Write(&buf, binary.BigEndian, uint16(2)) // 2 country codes
	buf.WriteString("US")
	buf.WriteString("CN")

	compressed, err := tgeo.CompressGzip(buf.Bytes())
	if err != nil {
		t.Fatalf("CompressGzip: %v", err)
	}
	return compressed
}

func TestTable_BasicFetch(t *testing.T) {
	gzData := buildTestTGEOGzip(t)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"test-v1"`)
		w.Write(gzData)
	}))
	defer ts.Close()

	table, err := Table(context.Background(), WithURL(ts.URL), WithClient(ts.Client()))
	if err != nil {
		t.Fatalf("Table: %v", err)
	}
	if table.EntryCount() != 2 {
		t.Errorf("entries = %d, want 2", table.EntryCount())
	}
}

func TestTable_304ReturnsCachedTable(t *testing.T) {
	gzData := buildTestTGEOGzip(t)
	etag := `"test-v1"`
	reqCount := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqCount++
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", etag)
		w.Write(gzData)
	}))
	defer ts.Close()

	// Override the package-level default cache so tests are isolated.
	opts := []Option{WithURL(ts.URL), WithClient(ts.Client())}

	table1, err := Table(context.Background(), opts...)
	if err != nil {
		t.Fatalf("first Table: %v", err)
	}

	table2, err := Table(context.Background(), opts...)
	if err != nil {
		t.Fatalf("second Table: %v", err)
	}

	if reqCount != 2 {
		t.Errorf("expected 2 HTTP requests, got %d", reqCount)
	}
	if table1.EntryCount() != table2.EntryCount() {
		t.Errorf("tables differ: %d vs %d entries", table1.EntryCount(), table2.EntryCount())
	}
}

func TestTable_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	_, err := Table(context.Background(), WithURL(ts.URL), WithClient(ts.Client()))
	if err == nil {
		t.Fatal("expected error on 500")
	}
}
