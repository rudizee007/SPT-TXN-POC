package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// mirrorBase returns the public mirror-node REST base URL for a network. The
// mirror node is read-only, free, and requires no key — so the verify path
// below is trust-minimized and anyone can run it.
func mirrorBase(network string) (string, error) {
	switch network {
	case "testnet":
		return "https://testnet.mirrornode.hedera.com", nil
	case "mainnet":
		return "https://mainnet-public.mirrornode.hedera.com", nil
	case "previewnet":
		return "https://previewnet.mirrornode.hedera.com", nil
	default:
		return "", fmt.Errorf("unknown network %q (want testnet|mainnet|previewnet)", network)
	}
}

type mirrorMessage struct {
	ConsensusTimestamp string `json:"consensus_timestamp"`
	Message            string `json:"message"` // base64-encoded message body
	SequenceNumber     int64  `json:"sequence_number"`
	TopicID            string `json:"topic_id"`
}

type mirrorPage struct {
	Messages []mirrorMessage `json:"messages"`
	Links    struct {
		Next string `json:"next"`
	} `json:"links"`
}

// AnchorProof is the public, keyless evidence that a hash was anchored: the HCS
// consensus timestamp and sequence number assigned by the network.
type AnchorProof struct {
	Hash               string
	Type               AnchorType
	TopicID            string
	SequenceNumber     int64
	ConsensusTimestamp string
}

// fetchTopicMessages returns every message body on a topic (base64-decoded, in
// consensus order) from the public mirror node — no key, no cost. Used by DID
// resolution to fold the topic's events.
func fetchTopicMessages(network, topicID string, timeout time.Duration) ([][]byte, error) {
	base, err := mirrorBase(network)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: timeout}
	var out [][]byte
	next := fmt.Sprintf("/api/v1/topics/%s/messages?limit=100&order=asc", url.PathEscape(topicID))
	for pages := 0; next != "" && pages < 100; pages++ {
		resp, err := client.Get(base + next)
		if err != nil {
			return nil, fmt.Errorf("mirror GET: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("mirror node HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var page mirrorPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode mirror response: %w", err)
		}
		for _, m := range page.Messages {
			raw, err := base64.StdEncoding.DecodeString(m.Message)
			if err != nil {
				continue
			}
			out = append(out, raw)
		}
		next = page.Links.Next
	}
	return out, nil
}

// VerifyOnMirror scans a topic's messages on the public mirror node (no key, no
// cost) for an anchor envelope carrying the given hash, returning the consensus
// timestamp + sequence number that prove WHEN it was anchored. It pages through
// results following the mirror node's own `links.next`, with a defensive cap.
func VerifyOnMirror(network, topicID, hashHex string, timeout time.Duration) (*AnchorProof, error) {
	base, err := mirrorBase(network)
	if err != nil {
		return nil, err
	}
	want := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(hashHex)), "0x")

	client := &http.Client{Timeout: timeout}
	next := fmt.Sprintf("/api/v1/topics/%s/messages?limit=100&order=asc", url.PathEscape(topicID))
	for pages := 0; next != "" && pages < 100; pages++ {
		resp, err := client.Get(base + next)
		if err != nil {
			return nil, fmt.Errorf("mirror GET: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("mirror node HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		var page mirrorPage
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("decode mirror response: %w", err)
		}
		for _, m := range page.Messages {
			raw, err := base64.StdEncoding.DecodeString(m.Message)
			if err != nil {
				continue // not our message
			}
			env, err := ParseEnvelope(raw)
			if err != nil {
				continue // not an SPT-Txn anchor envelope
			}
			if env.Hash == want {
				return &AnchorProof{
					Hash:               env.Hash,
					Type:               env.Type,
					TopicID:            m.TopicID,
					SequenceNumber:     m.SequenceNumber,
					ConsensusTimestamp: m.ConsensusTimestamp,
				}, nil
			}
		}
		next = page.Links.Next
	}
	return nil, fmt.Errorf("no anchor for hash %s found on topic %s", want, topicID)
}
