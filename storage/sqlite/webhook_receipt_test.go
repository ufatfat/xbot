package sqlite

import (
	"testing"
	"time"

	"xbot/event"
)

func TestTriggerServiceClaimWebhookRequestPersistsReplayReceipt(t *testing.T) {
	db := openTestDB(t)
	service := NewTriggerService(db)
	if err := service.AddTrigger(&event.Trigger{
		ID: "trg_receipt", EventType: "webhook", Channel: "web", ChatID: "c",
		SenderID: "u", MessageTpl: "message", Enabled: true, CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	duplicate, err := service.ClaimWebhookRequest("trg_receipt", "request_1234567890", "digest-a", now)
	if err != nil || duplicate {
		t.Fatalf("first claim duplicate=%v err=%v", duplicate, err)
	}
	duplicate, err = service.ClaimWebhookRequest("trg_receipt", "request_1234567890", "digest-a", now)
	if err != nil || !duplicate {
		t.Fatalf("repeat claim duplicate=%v err=%v", duplicate, err)
	}
	if _, err := service.ClaimWebhookRequest("trg_receipt", "request_1234567890", "digest-b", now); err == nil {
		t.Fatal("request ID reuse with another body must fail")
	}
}
