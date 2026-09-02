package sshclient

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

type Store struct {
	db     *sql.DB
	cipher cipher.AEAD
}

func NewStore(ctx context.Context, db *sql.DB, keyPath string) (*Store, error) {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS ssh_connections(
 id TEXT PRIMARY KEY,owner_id TEXT NOT NULL,name TEXT NOT NULL,host TEXT NOT NULL,port INTEGER NOT NULL,
 username TEXT NOT NULL,auth_type TEXT NOT NULL CHECK(auth_type IN('password','key')),
 secret BYTEA NOT NULL,fingerprint TEXT NOT NULL DEFAULT '',revision BIGINT NOT NULL DEFAULT 1);
 CREATE INDEX IF NOT EXISTS ssh_connections_owner ON ssh_connections(owner_id);`)
	if err != nil {
		return nil, err
	}
	var count int
	if err = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM ssh_connections").Scan(&count); err != nil {
		return nil, err
	}
	key, err := loadKey(keyPath, count == 0)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Store{db: db, cipher: aead}, nil
}

const connectionColumns = "id,owner_id,name,host,port,username,auth_type,secret,fingerprint,revision"

type scanner interface{ Scan(...any) error }

func scan(row scanner) (Connection, error) {
	var c Connection
	err := row.Scan(&c.ID, &c.Owner, &c.Name, &c.Host, &c.Port, &c.Username, &c.AuthType, &c.Secret, &c.Fingerprint, &c.Revision)
	return c, err
}
func (s *Store) Get(ctx context.Context, id, user string, all bool) (Connection, error) {
	return scan(s.db.QueryRowContext(ctx, "SELECT "+connectionColumns+" FROM ssh_connections WHERE id=$1 AND (owner_id=$2 OR $3::integer=1)", id, user, accessFlag(all)))
}
func (s *Store) List(ctx context.Context, user string, all bool) ([]Connection, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT "+connectionColumns+" FROM ssh_connections WHERE owner_id=$1 OR $2::integer=1 ORDER BY name,id LIMIT 1000", user, accessFlag(all))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	list := []Connection{}
	for rows.Next() {
		c, err := scan(rows)
		if err != nil {
			return nil, err
		}
		c.Secret = nil
		list = append(list, c)
	}
	return list, rows.Err()
}
func (s *Store) Save(ctx context.Context, id, user string, all bool, in Input) (Connection, error) {
	if err := in.Validate(); err != nil {
		return Connection{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Connection{}, err
	}
	defer tx.Rollback()
	c := Connection{ID: id, Owner: user}
	if id != "" {
		c, err = scan(tx.QueryRowContext(ctx, "SELECT "+connectionColumns+" FROM ssh_connections WHERE id=$1 AND (owner_id=$2 OR $3::integer=1) FOR UPDATE", id, user, accessFlag(all)))
		if err != nil {
			return c, err
		}
		if c.Revision != in.Revision {
			return c, ErrConflict
		}
		if c.AuthType != in.AuthType && in.Credential == nil {
			return c, ErrInvalid
		}
		if c.Host != in.Host || c.Port != in.Port {
			c.Fingerprint = ""
		}
	} else {
		if in.Credential == nil {
			return c, ErrInvalid
		}
		c.ID = "ssh_" + uuid.NewString()
		// Serialize creation to keep the catalog bounded.
		if _, err = tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(739523001)"); err != nil {
			return c, err
		}
		var count int
		if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM ssh_connections").Scan(&count); err != nil {
			return c, err
		}
		if count >= 1000 {
			return c, ErrBusy
		}
	}
	c.Name = in.Name
	c.Host = in.Host
	c.Port = in.Port
	c.Username = in.Username
	c.AuthType = in.AuthType
	if in.Credential != nil {
		plain, _ := json.Marshal(in.Credential)
		defer clear(plain)
		nonce := make([]byte, s.cipher.NonceSize())
		if _, err = rand.Read(nonce); err != nil {
			return c, err
		}
		c.Secret = s.cipher.Seal(nonce, nonce, plain, []byte(c.ID))
	}
	if id == "" {
		c.Revision = 1
		_, err = tx.ExecContext(ctx, `INSERT INTO ssh_connections(id,owner_id,name,host,port,username,auth_type,secret) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, c.ID, c.Owner, c.Name, c.Host, c.Port, c.Username, c.AuthType, c.Secret)
	} else {
		c.Revision++
		_, err = tx.ExecContext(ctx, `UPDATE ssh_connections SET name=$2,host=$3,port=$4,username=$5,auth_type=$6,secret=$7,fingerprint=$8,revision=$9 WHERE id=$1`, c.ID, c.Name, c.Host, c.Port, c.Username, c.AuthType, c.Secret, c.Fingerprint, c.Revision)
	}
	if err != nil {
		return c, err
	}
	return c, tx.Commit()
}
func (s *Store) Credential(c Connection) (Credential, error) {
	var result Credential
	n := s.cipher.NonceSize()
	if len(c.Secret) < n {
		return result, errors.New("invalid encrypted credential")
	}
	plain, err := s.cipher.Open(nil, c.Secret[:n], c.Secret[n:], []byte(c.ID))
	if err != nil {
		return result, errors.New("SSH credential cannot be decrypted; restore original master key")
	}
	defer clear(plain)
	err = json.Unmarshal(plain, &result)
	return result, err
}
func (s *Store) Trust(ctx context.Context, c Connection, fingerprint string) error {
	if !ValidFingerprint(fingerprint) {
		return ErrInvalid
	}
	result, err := s.db.ExecContext(ctx, "UPDATE ssh_connections SET fingerprint=$2,revision=revision+1 WHERE id=$1 AND revision=$3", c.ID, fingerprint, c.Revision)
	return changed(result, err)
}
func (s *Store) Delete(ctx context.Context, c Connection) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM ssh_connections WHERE id=$1 AND revision=$2", c.ID, c.Revision)
	return changed(result, err)
}
func accessFlag(all bool) int {
	if all {
		return 1
	}
	return 0
}
func changed(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrConflict
	}
	return nil
}
func (s *Store) Check(ctx context.Context, c Connection) error {
	var revision int64
	if err := s.db.QueryRowContext(ctx, "SELECT revision FROM ssh_connections WHERE id=$1", c.ID).Scan(&revision); err != nil {
		return err
	}
	if revision != c.Revision {
		return fmt.Errorf("%w: SSH session closed", ErrConflict)
	}
	return nil
}
