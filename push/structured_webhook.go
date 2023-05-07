package push

import (
	"encoding/json"
	"net/http"

	"github.com/kataras/golog"
)

var _ = Pusher(&StructuredWebhook{})

type StructuredWebhook struct {
	Webhook
}

type StructureWebhookData struct {
	Title   string      `json:"title"`
	Content interface{} `json:"content"`
	Type    string      `json:"type"`
}

func NewStructuredWebhook(url string) Pusher {
	return &StructuredWebhook{
		Webhook{
			url:    url,
			log:    golog.Child("[StructuredWebhook]"),
			client: &http.Client{},
		},
	}
}

func (m *StructuredWebhook) PushStructuredMessage(title, msgType string, content interface{}) error {
	m.log.Infof("sending structured message %s", title)
	params := &StructureWebhookData{
		Content: content,
		Title:   title,
		Type:    msgType,
	}
	postBody, _ := json.Marshal(params)
	_, err := m.doPostRequest(m.url, "application/json", postBody)
	if err != nil {
		return err
	}
	return nil
}
