package delivery

import (
	"errors"
	"testing"

	"github.com/emersion/go-smtp"
)

func TestMergeLMTPResultsByRecipient(t *testing.T) {
	results := make(map[string]error)
	accepted := []string{"ok@example.test", "temporary@example.test", "permanent@example.test"}
	good := map[string]*smtp.DataResponse{accepted[0]: {StatusText: "delivered"}}
	failed := smtp.LMTPDataError{
		accepted[1]: {Code: 451, Message: "try later"},
		accepted[2]: {Code: 550, Message: "no mailbox"},
	}
	mergeLMTPResults(results, accepted, good, failed)
	if results[accepted[0]] != nil {
		t.Fatalf("successful delivery was retried: %v", results[accepted[0]])
	}
	if !IsTemporary(results[accepted[1]]) {
		t.Fatalf("451 must be temporary: %v", results[accepted[1]])
	}
	if IsTemporary(results[accepted[2]]) {
		t.Fatalf("550 must be permanent: %v", results[accepted[2]])
	}
}

func TestMergeLMTPResultsUnknownRecipientIsTemporary(t *testing.T) {
	results := make(map[string]error)
	mergeLMTPResults(results, []string{"unknown@example.test"}, nil, errors.New("connection reset"))
	if !IsTemporary(results["unknown@example.test"]) {
		t.Fatal("missing response must not be treated as success")
	}
}
