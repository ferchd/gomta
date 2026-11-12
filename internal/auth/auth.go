// Package auth loads submission credentials and verifies passwords.
package auth

import (
	"bufio"
	"crypto/subtle"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Store is an immutable user database loaded from users.txt.
type Store struct {
	users map[string]entry
}

type entry struct {
	hash  []byte
	plain string // only for explicit "plain:" development entries
}

// Load reads users.txt. Each non-comment line is either:
//
//	user@example.com:$2a$12$...        (bcrypt, recommended)
//	user@example.com:plain:password    (development only)
func Load(path string) (*Store, error) {
	store := &Store{users: make(map[string]entry)}
	if path == "" {
		return store, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil
		}
		return nil, fmt.Errorf("read users file: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, secret, ok := strings.Cut(line, ":")
		if !ok || user == "" || secret == "" {
			return nil, fmt.Errorf("%s:%d: expected user:bcrypt-hash", path, lineNo)
		}
		user = strings.ToLower(strings.TrimSpace(user))
		if strings.HasPrefix(secret, "plain:") {
			store.users[user] = entry{plain: strings.TrimPrefix(secret, "plain:")}
			continue
		}
		if !strings.HasPrefix(secret, "$2") {
			return nil, fmt.Errorf("%s:%d: secret must be a bcrypt hash or plain:password", path, lineNo)
		}
		store.users[user] = entry{hash: []byte(secret)}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read users file: %w", err)
	}
	return store, nil
}

// Len returns the number of configured users.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	return len(s.users)
}

// HasUser reports whether username exists (case-insensitive).
func (s *Store) HasUser(username string) bool {
	if s == nil {
		return false
	}
	_, ok := s.users[strings.ToLower(strings.TrimSpace(username))]
	return ok
}

// Authenticate verifies a username/password pair. It performs a dummy bcrypt
// comparison for unknown users to reduce timing differences.
func (s *Store) Authenticate(username, password string) bool {
	if s == nil {
		return false
	}
	username = strings.ToLower(strings.TrimSpace(username))
	e, ok := s.users[username]
	if !ok {
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$C6UzMDM.H6dfI/f/IKcEeO7pV6XQ9i7bF0nG6D8uK1q5Q0eG1J8m2"), []byte(password))
		return false
	}
	if e.plain != "" {
		return subtle.ConstantTimeCompare([]byte(e.plain), []byte(password)) == 1
	}
	return bcrypt.CompareHashAndPassword(e.hash, []byte(password)) == nil
}

// HashPassword returns a bcrypt hash suitable for users.txt.
func HashPassword(password string) (string, error) {
	if len(password) < 8 {
		return "", fmt.Errorf("password must be at least 8 characters")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// WriteUser appends or replaces a user in the given users.txt file.
func WriteUser(path, username, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return WriteUserHash(path, username, hash)
}

// WriteUserHash appends or replaces a user with a pre-computed bcrypt hash.
func WriteUserHash(path, username, hash string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		return fmt.Errorf("username is required")
	}
	var lines []string
	if raw, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
			if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			user, _, ok := strings.Cut(line, ":")
			if ok && strings.EqualFold(strings.TrimSpace(user), username) {
				continue
			}
			lines = append(lines, line)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	lines = append(lines, username+":"+hash)
	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0o600)
}
