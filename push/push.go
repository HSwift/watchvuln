package push

import (
	"fmt"
	"github.com/zema1/watchvuln/grab"
	"reflect"
)

type Pusher interface {
	PushText(s string) error
	PushMarkdown(title, content string) error
}

type MultiPusher struct {
	pushers []Pusher
}

func Multi(pushers ...Pusher) *MultiPusher {
	return &MultiPusher{pushers: pushers}
}

func (m *MultiPusher) PushText(s string) error {
	for _, push := range m.pushers {
		if err := push.PushText(s); err != nil {
			return err
		}
	}
	return nil
}

func (m *MultiPusher) PushMarkdown(title string, content interface{}) error {
	msgType := ""
	renderedMsg := ""
	switch v := content.(type) {
	case *InitialMsg:
		msgType = "initial_msg"
		renderedMsg = RenderInitialMsg(v)
	case *grab.VulnInfo:
		msgType = "vuln_info"
		renderedMsg = RenderVulnInfo(v)
	default:
		return fmt.Errorf("unsupported message type %s, it can not be here", reflect.TypeOf(content))
	}
	for _, push := range m.pushers {
		if structuredWebhook, ok := push.(*StructuredWebhook); ok {
			if err := structuredWebhook.PushStructuredMessage(title, msgType, content); err != nil {
				return err
			}
		} else if err := push.PushMarkdown(title, renderedMsg); err != nil {
			return err
		}
	}
	return nil
}
