package db

import (
	"database/sql"
	"errors"
)

var ErrQNAPIdentityConflict = errors.New("a local Koffan account already uses this QTS username")

// EnsureQNAPUser provisions only identities verified by the QTS API. Existing
// local accounts are never silently linked by matching usernames.
func EnsureQNAPUser(username string, isAdmin bool) (*User, error) {
	tx, err := DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var user User
	err = tx.QueryRow(`SELECT u.id, u.username, u.display_name, u.is_admin
		FROM qnap_users q JOIN users u ON u.id = q.user_id WHERE q.username = ?`, username).
		Scan(&user.ID, &user.Username, &user.DisplayName, &user.IsAdmin)
	if errors.Is(err, sql.ErrNoRows) {
		var exists bool
		if err := tx.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			return nil, ErrQNAPIdentityConflict
		}
		// This is not a valid bcrypt hash, so local-password login is impossible.
		res, err := tx.Exec("INSERT INTO users(username, display_name, password_hash, is_admin) VALUES (?, ?, '!', ?)", username, username, isAdmin)
		if err != nil {
			return nil, err
		}
		user.ID, err = res.LastInsertId()
		if err != nil {
			return nil, err
		}
		user.Username, user.DisplayName, user.IsAdmin = username, username, isAdmin
		if _, err = tx.Exec("INSERT INTO qnap_users(username, user_id) VALUES (?, ?)", username, user.ID); err != nil {
			return nil, err
		}
		// Preserve the old shared shopping data for the first QTS administrator.
		// Other users always start in a new, private workspace.
		var members int
		if err := tx.QueryRow("SELECT COUNT(*) FROM workspace_members WHERE workspace_id = ?", DefaultWorkspaceID).Scan(&members); err != nil {
			return nil, err
		}
		workspaceID := DefaultWorkspaceID
		if !isAdmin || members > 0 {
			res, err := tx.Exec("INSERT INTO workspaces(name, icon) VALUES (?, ?)", username, DefaultWorkspaceIcon)
			if err != nil {
				return nil, err
			}
			workspaceID, err = res.LastInsertId()
			if err != nil {
				return nil, err
			}
		}
		if _, err := tx.Exec("INSERT INTO workspace_members(workspace_id, user_id, role) VALUES (?, ?, ?)", workspaceID, user.ID, RoleOwner); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if user.IsAdmin != isAdmin {
		// QTS remains authoritative for privilege changes on every request.
		if _, err := tx.Exec("UPDATE users SET is_admin = ? WHERE id = ?", isAdmin, user.ID); err != nil {
			return nil, err
		}
		user.IsAdmin = isAdmin
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &user, nil
}

// A Koffan session remembers workspace selection, but authorizes nothing without
// the same live QTS identity and SID. Only a digest of that SID is persisted.
func CreateQNAPSession(id string, expiresAt, userID, workspaceID int64, sidHash string) error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("INSERT INTO sessions(id, expires_at, user_id, workspace_id) VALUES (?, ?, ?, ?)", id, expiresAt, userID, workspaceID); err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO qnap_sessions(session_id, sid_hash) VALUES (?, ?)", id, sidHash); err != nil {
		return err
	}
	return tx.Commit()
}

func GetQNAPSession(id, sidHash string) (*Session, error) {
	var session Session
	err := DB.QueryRow(`SELECT s.id, s.expires_at, s.user_id, s.workspace_id
		FROM sessions s JOIN qnap_sessions q ON q.session_id = s.id
		WHERE s.id = ? AND q.sid_hash = ?`, id, sidHash).
		Scan(&session.ID, &session.ExpiresAt, &session.UserID, &session.WorkspaceID)
	return &session, err
}

func QNAPUserID(username string) (int64, error) {
	var id int64
	err := DB.QueryRow("SELECT user_id FROM qnap_users WHERE username = ?", username).Scan(&id)
	return id, err
}
