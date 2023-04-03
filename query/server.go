package query

import (
	"encoding/json"
	"github.com/kataras/golog"
	"github.com/zema1/watchvuln/ent"
	"github.com/zema1/watchvuln/ent/vulninformation"
	"io"
	"net/http"
)

var log = golog.Child("[queryAPI]")

type Handler struct {
	dbClient *ent.Client
}

type ResponseObject struct {
	Code    int                    `json:"code"`
	Data    []*ent.VulnInformation `json:"data"`
	Message string                 `json:"message"`
}

func (h *Handler) indexHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	title := q.Get("title")
	cve := q.Get("cve")
	var all []*ent.VulnInformation
	var err error
	if title != "" {
		all, err = h.dbClient.VulnInformation.Query().Where(vulninformation.TitleContainsFold(title)).All(r.Context())
	} else if cve != "" {
		all, err = h.dbClient.VulnInformation.Query().Where(vulninformation.CveEqualFold(cve)).All(r.Context())
	} else {
		ro := ResponseObject{400, nil, "must specify title or cve number"}
		w.WriteHeader(400)
		writeJson(ro, w)
		return
	}
	if err != nil {
		log.Error(err)
		ro := ResponseObject{500, nil, err.Error()}
		w.WriteHeader(500)
		writeJson(ro, w)
	} else {
		all = aggregation(all)
		ro := ResponseObject{200, all, "success"}
		w.WriteHeader(200)
		writeJson(ro, w)
	}
}

func aggregation(vulns []*ent.VulnInformation) []*ent.VulnInformation {
	vulnMap := make(map[string]*ent.VulnInformation)
	for _, vuln := range vulns {
		if v, ok := vulnMap[vuln.Cve]; !ok {
			vulnMap[vuln.Cve] = vuln
		} else {
			if len(v.Description) < len(vuln.Description) {
				vulnMap[vuln.Cve].Description = vuln.Description
			}
			if len(v.Tags) < len(vuln.Tags) {
				vulnMap[vuln.Cve].Tags = vuln.Tags
			}
			if len(v.References) < len(vuln.References) {
				vulnMap[vuln.Cve].Description = vuln.Description
			}
		}
	}
	vulnList := make([]*ent.VulnInformation, 0)
	for _, v := range vulnMap {
		vulnList = append(vulnList, v)
	}
	return vulnList
}

func writeJson(v interface{}, w io.Writer) {
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		log.Error(err)
	}
}

func Run(addr string, db *ent.Client) {
	log.Info("Server Running")
	handler := Handler{
		dbClient: db,
	}
	http.HandleFunc("/", handler.indexHandler)
	go http.ListenAndServe(addr, nil)
}
