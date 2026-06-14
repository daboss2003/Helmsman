package alert

import (
	"context"
	"strings"
	"testing"
)

func TestHeaderSafeStripsInjection(t *testing.T) {
	got := headerSafe("Subject\r\nBcc: evil@x\x00 more")
	if strings.ContainsAny(got, "\r\n\x00") {
		t.Errorf("headerSafe left a control char: %q", got)
	}
}

// The SSRF guard refuses to deliver to loopback / link-local (incl. the cloud
// metadata IP) regardless of channel kind — and the error never echoes the URL.
func TestChannelGuardBlocksLoopbackAndMetadata(t *testing.T) {
	ctx := context.Background()
	for _, raw := range []string{"http://127.0.0.1:9/hook", "http://169.254.169.254/latest", "http://[::1]:9/x"} {
		c := webhookChannel{URL: raw}
		err := c.Send(ctx, Notification{Title: "t", Body: "b"})
		if err == nil {
			t.Errorf("send to %q should be blocked", raw)
		}
		if err != nil && strings.Contains(err.Error(), raw) {
			t.Errorf("error leaked the URL: %v", err)
		}
	}
}

// A delivery error never contains the secret-bearing URL (Telegram token /
// Slack-Discord webhook URL).
func TestDeliveryErrorOmitsURL(t *testing.T) {
	// nonexistent host → a *url.Error; sanitizeHTTPErr must drop the URL.
	c := telegramChannel{BotToken: "12345:SECRET-BOT-TOKEN", ChatID: "1"}
	err := c.Send(context.Background(), Notification{Title: "t"})
	if err == nil {
		t.Skip("telegram unexpectedly reachable")
	}
	if strings.Contains(err.Error(), "SECRET-BOT-TOKEN") {
		t.Errorf("telegram error leaked the bot token: %v", err)
	}
}

func TestBuildChannelRejectsUnknownFields(t *testing.T) {
	if _, err := BuildChannel("webhook", []byte(`{"url":"https://x/h","secret":"s"}`)); err != nil {
		t.Errorf("valid webhook config rejected: %v", err)
	}
	if _, err := BuildChannel("webhook", []byte(`{"url":"https://x","evil":"smuggled"}`)); err == nil {
		t.Error("unknown field should be rejected (DisallowUnknownFields)")
	}
	if _, err := BuildChannel("nope", []byte(`{}`)); err == nil {
		t.Error("unknown kind should be rejected")
	}
}

func TestSMTPRejectsBadAddresses(t *testing.T) {
	c := smtpChannel{Host: "smtp.example.com", Port: 587, From: "not an address", To: "ops@example.com"}
	if err := c.Send(context.Background(), Notification{Title: "t"}); err == nil {
		t.Error("bad from address should be rejected before any network use")
	}
}
