package ftkos

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchFeeds(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/feodo":
			w.Write([]byte(`[{"ip_address":"50.16.16.211","port":8080,"status":"online","malware":"QakBot"},{"ip_address":"x","port":1}]`))
		case "/threatfox":
			w.Write([]byte(`{"1":[{"ioc_value":"evil-c2.example.com","ioc_type":"domain","malware_printable":"Cobalt Strike"}],"2":[{"ioc_value":"45.9.148.108:443","ioc_type":"ip:port","malware_printable":"Sliver"}]}`))
		case "/urlhaus":
			w.Write([]byte("# comment\n\"1\",\"2026-11-25 10:00:00\",\"http://bad.example.net/x.exe\",\"online\",\"\",\"malware_download\",\"exe\",\"https://urlhaus.abuse.ch/url/1/\",\"r\"\n"))
		case "/openphish":
			w.Write([]byte("https://login-micros0ft.example.org/auth\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	old := FeedBase
	FeedBase = map[string]string{"feodo": ts.URL + "/feodo", "threatfox": ts.URL + "/threatfox", "urlhaus": ts.URL + "/urlhaus", "openphish": ts.URL + "/openphish"}
	defer func() { FeedBase = old }()
	m := &Manager{Dir: t.TempDir()}
	s, err := m.FetchFeeds()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.C2) != 2 || s.C2[0].Family != "QakBot" || s.C2[1].IP != "45.9.148.108" || len(s.Domains) != 1 || len(s.URLs) != 1 || s.URLs[0].Host != "bad.example.net" || len(s.Phish) != 1 {
		t.Fatalf("parsed %+v", s)
	}
	if l := m.LoadFeed(""); l == nil || l.Date != s.Date {
		t.Fatal("snapshot not stored")
	}
}
