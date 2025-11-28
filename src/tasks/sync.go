package tasks

import (
	"context"
	"fmt"
	"reflect"
	"sync/atomic"
	"time"

	"github.com/iedon/peerapi-agent/api"
	"github.com/iedon/peerapi-agent/config"
	"github.com/iedon/peerapi-agent/logger"
	"github.com/iedon/peerapi-agent/session"
)

// SessionSyncTask synchronizes local sessions with the PeerAPI server
type SessionSyncTask struct {
	cfg        *config.Config
	logger     *logger.Logger
	apiClient  *api.Client
	sessionMgr *session.Manager
	running    atomic.Bool
}

// NewSessionSyncTask creates a new session sync task
func NewSessionSyncTask(cfg *config.Config, log *logger.Logger, apiClient *api.Client, sessionMgr *session.Manager) *SessionSyncTask {
	return &SessionSyncTask{
		cfg:        cfg,
		logger:     log,
		apiClient:  apiClient,
		sessionMgr: sessionMgr,
	}
}

// Run runs the session sync task
func (t *SessionSyncTask) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(t.cfg.PeerAPI.SyncInterval) * time.Second)
	defer ticker.Stop()

	// Sync sessions immediately on startup
	t.syncSessions(ctx)

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("Session sync task shutting down...")
			sessionCount := len(t.sessionMgr.List())
			t.logger.Info("Cleaning up %d managed BGP sessions", sessionCount)
			return
		case <-ticker.C:
			t.syncSessions(ctx)
		}
	}
}

// TriggerSync triggers a manual synchronization
func (t *SessionSyncTask) TriggerSync(ctx context.Context) {
	t.logger.Debug("Manual session sync triggered")
	go t.syncSessions(ctx)
}

// syncSessions synchronizes local sessions with the PeerAPI server
func (t *SessionSyncTask) syncSessions(ctx context.Context) {
	// Prevent concurrent sync operations
	if !t.running.CompareAndSwap(false, true) {
		t.logger.Debug("Session sync already in progress, skipping")
		return
	}
	defer t.running.Store(false)

	// Fetch sessions from PeerAPI
	remoteSessions, err := t.apiClient.GetSessions(ctx)
	if err != nil {
		t.logger.Error("Failed to get remote sessions: %v", err)
		return
	}

	localSessions := t.sessionMgr.List()
	t.logger.Info("Syncing %d remote sessions with %d local sessions...", len(remoteSessions), len(localSessions))

	nextLocal := make(map[string]*session.Session)
	remoteSessionUUIDs := make(map[string]struct{}, len(remoteSessions))

	// Process remote sessions
	for i := range remoteSessions {
		apiSess := &remoteSessions[i]
		remoteSessionUUIDs[apiSess.UUID] = struct{}{}

		// Convert API session to internal session
		sess := apiSess.ToSession()

		oldSession := t.sessionMgr.Get(sess.UUID)
		if oldSession == nil {
			// New session
			t.processNewSession(ctx, sess, nextLocal)
		} else {
			// Existing session that may have changed
			t.processChangedSession(ctx, sess, oldSession, nextLocal)
		}
	}

	// Handle sessions that were deleted from the remote side
	for _, localSession := range localSessions {
		if _, exists := remoteSessionUUIDs[localSession.UUID]; !exists {
			t.processDeletedSession(ctx, localSession)
		}
	}

	// Update session manager with new state
	t.sessionMgr.Replace(nextLocal)
}

// processNewSession handles a newly discovered session
func (t *SessionSyncTask) processNewSession(ctx context.Context, sess *session.Session, nextLocal map[string]*session.Session) {
	// Validate session inputs if not torn down
	t.validateSession(ctx, sess)

	var lastError string
	switch sess.Status {
	case session.StatusQueuedForSetup:
		if err := t.sessionMgr.ConfigureSession(sess); err != nil {
			lastError = err.Error()
			sess.Status = session.StatusProblem
			t.logger.Error("Failed to configure session %s: %v", sess.UUID, err)
		} else {
			sess.Status = session.StatusEnabled
			t.logger.Info("Session %s enabled and configured successfully", sess.UUID)
		}
		if err := t.apiClient.ReportSessionStatus(ctx, sess.UUID, sess.Status, lastError); err != nil {
			t.logger.Error("Failed to report status for session %s: %v", sess.UUID, err)
		}

	case session.StatusEnabled:
		if err := t.sessionMgr.ConfigureSession(sess); err != nil {
			lastError = err.Error()
			sess.Status = session.StatusProblem
			t.logger.Error("Failed to configure session %s: %v", sess.UUID, err)
		} else {
			t.logger.Info("Session %s enabled and configured successfully", sess.UUID)
		}
		if err := t.apiClient.ReportSessionStatus(ctx, sess.UUID, sess.Status, lastError); err != nil {
			t.logger.Error("Failed to report status for session %s: %v", sess.UUID, err)
		}

	case session.StatusProblem:
		if err := t.sessionMgr.ConfigureSession(sess); err != nil {
			lastError = err.Error()
			t.logger.Error("Failed to configure session %s: %v", sess.UUID, err)
		} else {
			sess.Status = session.StatusEnabled
			t.logger.Info("Session %s recovered from PROBLEM to ENABLED", sess.UUID)
		}
		if err := t.apiClient.ReportSessionStatus(ctx, sess.UUID, sess.Status, lastError); err != nil {
			t.logger.Error("Failed to report status for session %s: %v", sess.UUID, err)
		}

	case session.StatusQueuedForDelete:
		if err := t.apiClient.ReportSessionStatus(ctx, sess.UUID, session.StatusDeleted, ""); err == nil {
			sess.Status = session.StatusDeleted
			t.logger.Info("Session %s queued for deletion, marked as deleted", sess.UUID)
		}

	default:
		t.logger.Debug("Skipping session %s with status %d", sess.UUID, sess.Status)
	}

	nextLocal[sess.UUID] = sess
}

// processChangedSession handles a session that has changed configuration
func (t *SessionSyncTask) processChangedSession(ctx context.Context, newSession, oldSession *session.Session, nextLocal map[string]*session.Session) {
	if reflect.DeepEqual(*newSession, *oldSession) {
		// No changes, just copy to the new map
		nextLocal[newSession.UUID] = newSession
		return
	}

	// Special case: delete torn down session,
	// so that already torn down sessions changed to delete status will not be torn down again
	isDeletingTorndownSession := (oldSession.Status == session.StatusTeardown &&
		(newSession.Status == session.StatusQueuedForDelete || newSession.Status == session.StatusDeleted))

	if !isDeletingTorndownSession {
		t.validateSession(ctx, newSession)
	}

	// Handle session based on its new status
	var lastError string
	switch newSession.Status {
	case session.StatusDisabled, session.StatusDeleted, session.StatusTeardown:
		if err := t.sessionMgr.DeleteSession(oldSession); err != nil {
			t.logger.Warn("Failed to delete session %s: %v", newSession.UUID, err)
		}
		t.logger.Info("Session %s deleted due to status change to %d", newSession.UUID, newSession.Status)

	case session.StatusQueuedForDelete:
		if err := t.sessionMgr.DeleteSession(oldSession); err != nil {
			t.logger.Warn("Failed to delete session %s: %v", newSession.UUID, err)
		}
		newSession.Status = session.StatusDeleted
		if err := t.apiClient.ReportSessionStatus(ctx, newSession.UUID, session.StatusDeleted, ""); err != nil {
			t.logger.Error("Failed to report deletion for session %s: %v", newSession.UUID, err)
		} else {
			t.logger.Info("Session %s deleted and status updated", newSession.UUID)
		}

	case session.StatusQueuedForSetup:
		if err := t.sessionMgr.ConfigureSession(newSession); err != nil {
			newSession.Status = session.StatusProblem
			lastError = err.Error()
			t.logger.Error("Failed to reconfigure session %s: %v", newSession.UUID, err)
		} else {
			newSession.Status = session.StatusEnabled
			t.logger.Info("Session %s enabled and configured successfully", newSession.UUID)
		}
		if err := t.apiClient.ReportSessionStatus(ctx, newSession.UUID, newSession.Status, lastError); err != nil {
			t.logger.Error("Failed to report status for session %s: %v", newSession.UUID, err)
		}

	case session.StatusEnabled:
		if err := t.sessionMgr.ConfigureSession(newSession); err != nil {
			newSession.Status = session.StatusProblem
			lastError = err.Error()
			t.logger.Error("Failed to configure session %s: %v", newSession.UUID, err)
		} else {
			t.logger.Info("Session %s enabled and configured successfully", newSession.UUID)
		}
		if err := t.apiClient.ReportSessionStatus(ctx, newSession.UUID, newSession.Status, lastError); err != nil {
			t.logger.Error("Failed to report status for session %s: %v", newSession.UUID, err)
		}

	case session.StatusProblem:
		if err := t.sessionMgr.ConfigureSession(newSession); err != nil {
			lastError = err.Error()
			t.logger.Error("Failed to configure session %s: %v", newSession.UUID, err)
		} else {
			newSession.Status = session.StatusEnabled
			t.logger.Info("Session %s recovered from PROBLEM to ENABLED", newSession.UUID)
		}
		if err := t.apiClient.ReportSessionStatus(ctx, newSession.UUID, newSession.Status, lastError); err != nil {
			t.logger.Error("Failed to report status for session %s: %v", newSession.UUID, err)
		}
	}

	// Update the session in the new map
	nextLocal[newSession.UUID] = newSession
}

// processDeletedSession handles a session that has been removed from the PeerAPI
func (t *SessionSyncTask) processDeletedSession(ctx context.Context, sess *session.Session) {
	// Check if context is cancelled (e.g., during shutdown)
	if ctx.Err() != nil {
		return
	}

	if err := t.sessionMgr.DeleteSession(sess); err != nil {
		t.logger.Error("Session %s removed from PeerAPI, but failed to remove locally: %v", sess.UUID, err)
		return
	}
	t.logger.Info("Session %s removed from PeerAPI and deleted locally", sess.UUID)
}

// validateSession validates session inputs and marks it as TEARDOWN if invalid
func (t *SessionSyncTask) validateSession(ctx context.Context, sess *session.Session) {
	if sess.Status == session.StatusTeardown {
		return
	}

	if err := session.ValidateSession(sess); err != nil {
		t.logger.Warn("Session %s has invalid configuration, tearing down: %v", sess.UUID, err)
		sess.Status = session.StatusTeardown
		if err := t.apiClient.ReportSessionStatus(ctx, sess.UUID, session.StatusTeardown, fmt.Sprintf("invalid configuration: %s", err.Error())); err != nil {
			t.logger.Error("Failed to report teardown status for session %s: %v", sess.UUID, err)
		}
	}
}
