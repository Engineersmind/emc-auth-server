// verify.go — tamper-evidence chain verification.
//
// Recomputes each row's hash from its persisted non-PII skeleton and checks
// both that it matches the stored row_hash (row not altered) and that its
// prev_hash links to the preceding row's row_hash (no row deleted/reordered).
// Any mismatch pinpoints the first broken row.

package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// VerifyResult reports the outcome of a chain verification pass.
type VerifyResult struct {
	// Intact is true when every checked row's hash and linkage verified.
	Intact bool `json:"intact"`
	// Checked is the number of rows verified.
	Checked int `json:"checked"`
	// BrokenAtID is the id of the first row whose hash/linkage failed, when any.
	BrokenAtID *string `json:"broken_at_id,omitempty"`
	// Detail is a human-readable description of the break (or "ok").
	Detail string `json:"detail"`
}

// VerifyChain walks the audit chain in insertion order and verifies integrity.
// tenantScope is accepted for API symmetry but the chain is global (single
// writer), so verification always runs over the whole chain; limit bounds the
// number of most-recent rows checked (0 → a safe default) to cap cost on large
// tables. Rows predating the hash-chain rollout (row_hash IS NULL) are skipped.
func (l *Logger) VerifyChain(ctx context.Context, limit int) (*VerifyResult, error) {
	if limit <= 0 || limit > 100000 {
		limit = 10000
	}

	// Pull the most-recent `limit` chained rows, then verify oldest→newest.
	rows, err := l.pool.Query(ctx, `
		SELECT id, tenant_id, user_id, agent_id, application_id, action, auth_method,
		       resource_type, resource_id, status, http_status, request_id,
		       created_at, row_hash, prev_hash
		FROM (
			SELECT * FROM audit_logs
			WHERE row_hash IS NOT NULL
			ORDER BY id DESC
			LIMIT $1
		) recent
		ORDER BY id ASC
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("verify query: %w", err)
	}
	defer rows.Close()

	res := &VerifyResult{Intact: true, Detail: "ok"}
	var expectedPrev *string // row_hash of the previous verified row; nil for the first

	for rows.Next() {
		var id int64
		var tenantID, userID, applicationID *int64
		var agentID *uuid.UUID
		var action, authMethod, resourceType, resourceID, status, requestID string
		var httpStatus *int16
		var createdAt time.Time
		var rowHash, prevHash *string
		if err := rows.Scan(
			&id, &tenantID, &userID, &agentID, &applicationID, &action, &authMethod,
			&resourceType, &resourceID, &status, &httpStatus, &requestID,
			&createdAt, &rowHash, &prevHash,
		); err != nil {
			return nil, fmt.Errorf("verify scan: %w", err)
		}

		e := Event{
			TenantID: tenantID, UserID: userID, AgentID: agentID, ApplicationID: applicationID,
			Action: action, AuthMethod: authMethod,
			ResourceType: resourceType, ResourceID: resourceID, RequestID: requestID,
			createdAt: createdAt,
		}
		hs := 0
		if httpStatus != nil {
			hs = int(*httpStatus)
		}
		prev := ""
		if prevHash != nil {
			prev = *prevHash
		}
		want := chainHash(prev, e, status, hs)

		idStr := fmt.Sprintf("%d", id)
		// Linkage: this row's prev_hash must equal the previous row's row_hash
		// (skipped for the first row of the checked window).
		if expectedPrev != nil && prev != *expectedPrev {
			res.Intact = false
			res.BrokenAtID = &idStr
			res.Detail = fmt.Sprintf("row %d prev_hash does not link to the preceding row", id)
			return res, nil
		}
		// Content: recomputed hash must equal the stored row_hash.
		if rowHash == nil || want != *rowHash {
			res.Intact = false
			res.BrokenAtID = &idStr
			res.Detail = fmt.Sprintf("row %d content hash mismatch — row altered", id)
			return res, nil
		}
		expectedPrev = rowHash
		res.Checked++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if res.Checked == 0 {
		res.Detail = "no chained rows to verify"
	}
	return res, nil
}
