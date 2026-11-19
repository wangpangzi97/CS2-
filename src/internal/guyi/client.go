// Package guyi implements the GuYi-Access v2 client protocol. No application or
// management secret belongs in a distributed client; sessions bootstrap over TLS.
package guyi

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"local/cs2-radar/internal/startupdiag"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Endpoint string `json:"endpoint"`
	AppKey   string `json:"app_key"`
	AppID    int64  `json:"app_id"`
	CAFile   string `json:"ca_file,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("读取 license.json: %w", err)
	}
	if len(b) > 16384 {
		return c, errors.New("授权配置过大")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, fmt.Errorf("授权配置格式: %w", err)
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return c, errors.New("授权配置包含多余内容")
	}
	if c.CAFile != "" && !filepath.IsAbs(c.CAFile) {
		c.CAFile = filepath.Join(filepath.Dir(path), c.CAFile)
	}
	return c, c.validate()
}

func (c Config) validate() error {
	u, err := url.Parse(c.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path == "" || u.RawPath != "" || strings.ContainsAny(c.Endpoint, "\r\n") {
		return errors.New("授权 endpoint 必须是完整 HTTPS API URL，禁止查询参数、用户信息和转义路径")
	}
	if !hex32(c.AppKey) || c.AppID <= 0 {
		return errors.New("请设置有效的公开 app_key 和 app_id（不是 api_secret）")
	}
	return nil
}

func hex32(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && s == strings.ToLower(s)
}

// derive is RFC 5869 HKDF-SHA256 with empty salt, one 32-byte output block.
// The target toolchain has no crypto/hkdf; interoperability is checked against PHP hash_hkdf.
func derive(secret, purpose string) ([]byte, error) {
	if !hex32(secret) {
		return nil, errors.New("无效的会话密钥")
	}
	b, _ := hex.DecodeString(secret)
	extract := hmac.New(sha256.New, make([]byte, 32))
	extract.Write(b)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write([]byte("guyi-v2/" + purpose))
	expand.Write([]byte{1})
	return expand.Sum(nil), nil
}

type Client struct {
	config    Config
	http      *http.Client
	deviceKey ed25519.PrivateKey
}

func New(c Config) (*Client, error) {
	if e := c.validate(); e != nil {
		return nil, e
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		b, e := os.ReadFile(c.CAFile)
		if e != nil {
			return nil, fmt.Errorf("读取授权 CA: %w", e)
		}
		pool, e := x509.SystemCertPool()
		if e != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("授权 CA 不包含有效证书")
		}
		t.TLSClientConfig.RootCAs = pool
	}
	return &Client{config: c, http: &http.Client{Transport: t, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// SetDeviceProofKey must run before concurrent use; it never exports the key.
func (c *Client) SetDeviceProofKey(key ed25519.PrivateKey) error {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key.Seed()), key) {
		return errors.New("invalid device proof key")
	}
	c.deviceKey = append(ed25519.PrivateKey(nil), key...)
	return nil
}

type Session struct {
	ID         string `json:"session_id"`
	Key        string `json:"session_key"`
	Version    int    `json:"key_version"`
	ExpiresAt  int64  `json:"expires_at"`
	ExpireTime string `json:"expire_time"`
}

type apiResponse struct {
	Code int             `json:"code"`
	Data json.RawMessage `json:"data"`
}
type envelope struct {
	Protocol   string `json:"protocol"`
	AAD        string `json:"aad"`
	Ciphertext string `json:"encrypted_data"`
}
type APIError struct{ Status int }

func (e *APIError) HTTPStatus() int { return e.Status }

func (e *APIError) Error() string {
	return fmt.Sprintf("授权服务器拒绝请求 (HTTP %d)，请检查卡密、绑定状态、版本或服务器时间", e.Status)
}

func (c *Client) request(ctx context.Context, action, device, card string, version int, s *Session) (result json.RawMessage, failure error) {
	defer func() {
		stages := map[string]startupdiag.Stage{"config": startupdiag.LicenseConfig, "activate": startupdiag.Activation, "heartbeat": startupdiag.LicenseHeartbeat}
		if stage, ok := stages[action]; ok && failure != nil {
			failure = startupdiag.Wrap(stage, failure)
		}
	}()
	data := map[string]string{"app_key": c.config.AppKey, "action": action}
	if device != "" {
		data["device_hash"] = device
	}
	if card != "" {
		data["card_code"] = card
	}
	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	n := make([]byte, 16)
	if _, err = rand.Read(n); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(n)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.config.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Nonce", nonce)
	req.Header.Set("X-Key-Version", strconv.Itoa(version))
	if s != nil {
		if !hex32(s.ID) || s.ExpiresAt <= time.Now().Unix() {
			return nil, errors.New("授权会话已过期")
		}
		key, e := derive(s.Key, "request-sign")
		if e != nil {
			return nil, e
		}
		digest := sha256.Sum256(body)
		canonical := strings.Join([]string{"v2", "POST", req.URL.Path, "session:" + s.ID, strconv.Itoa(version), timestamp, nonce, hex.EncodeToString(digest[:])}, "\n")
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(canonical))
		req.Header.Set("X-Session-Id", s.ID)
		req.Header.Set("X-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	if len(c.deviceKey) == ed25519.PrivateKeySize {
		digest := sha256.Sum256(body)
		text := strings.Join([]string{"guyi-device-v1", "POST", req.URL.Path, strconv.Itoa(version), timestamp, nonce, req.Header.Get("X-Session-Id"), hex.EncodeToString(digest[:])}, "\n")
		req.Header.Set("X-Device-Proof", base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.deviceKey, []byte(text))))
	}
	res, err := c.http.Do(req)
	if err != nil {
		return nil, startupdiag.Network(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20+1))
	if err != nil {
		return nil, errors.New("授权响应读取失败")
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("授权响应过大")
	}
	if res.StatusCode != http.StatusOK {
		return nil, &APIError{res.StatusCode}
	}
	if s != nil {
		var env envelope
		if json.Unmarshal(raw, &env) != nil || env.Protocol != "v2" {
			return nil, errors.New("拒绝未加密的受保护授权响应")
		}
		expected := fmt.Sprintf("v2:%d:%d:%s:200", c.config.AppID, version, nonce)
		if env.AAD != expected {
			return nil, errors.New("授权响应与本次请求不匹配")
		}
		wire, e := base64.StdEncoding.Strict().DecodeString(env.Ciphertext)
		if e != nil || len(wire) < 29 {
			return nil, errors.New("无效的授权密文")
		}
		key, e := derive(s.Key, "response-encrypt")
		if e != nil {
			return nil, e
		}
		block, e := aes.NewCipher(key)
		if e != nil {
			return nil, e
		}
		gcm, e := cipher.NewGCM(block)
		if e != nil {
			return nil, e
		}
		// PHP wire: IV(12) || tag(16) || ciphertext. Go wants ciphertext || tag.
		sealed := append(append([]byte{}, wire[28:]...), wire[12:28]...)
		raw, e = gcm.Open(nil, wire[:12], sealed, []byte(expected))
		if e != nil {
			return nil, errors.New("授权响应认证失败")
		}
	}
	var response apiResponse
	if json.Unmarshal(raw, &response) != nil || response.Code != 200 || len(response.Data) == 0 || string(response.Data) == "null" {
		return nil, errors.New("无效的授权成功响应")
	}
	return response.Data, nil
}

func (c *Client) Activate(ctx context.Context, card, device string) (Session, error) {
	var s Session
	if len(card) == 0 || len(card) > 50 || len(device) == 0 || len(device) > 100 || strings.ContainsRune(card, '\x00') || strings.ContainsRune(device, '\x00') {
		return s, startupdiag.Wrap(startupdiag.CardInput, errors.New("invalid card input"))
	}
	r, e := c.request(ctx, "config", "", "", 1, nil)
	if e != nil {
		return s, e
	}
	var config struct {
		Version int `json:"key_version"`
	}
	if json.Unmarshal(r, &config) != nil || config.Version < 1 || config.Version > 999999999 {
		return s, startupdiag.Wrap(startupdiag.LicenseConfig, errors.New("invalid protocol version"))
	}
	r, e = c.request(ctx, "activate", device, card, config.Version, nil)
	if e != nil {
		return s, e
	}
	if json.Unmarshal(r, &s) != nil || !hex32(s.ID) || !hex32(s.Key) || s.Version != config.Version || s.ExpiresAt <= time.Now().Unix() || s.ExpiresAt > time.Now().Add(20*time.Minute).Unix() {
		return Session{}, startupdiag.Wrap(startupdiag.Activation, errors.New("invalid license session"))
	}
	return s, nil
}

func (c *Client) Heartbeat(ctx context.Context, s Session, device string) error {
	r, e := c.request(ctx, "heartbeat", device, "", s.Version, &s)
	if e != nil {
		return e
	}
	var d struct {
		ExpireTime string `json:"expire_time"`
	}
	if json.Unmarshal(r, &d) != nil || d.ExpireTime == "" {
		return startupdiag.Wrap(startupdiag.LicenseHeartbeat, errors.New("invalid heartbeat"))
	}
	return nil
}

func (c *Client) Unbind(ctx context.Context, s Session, device string) error {
	r, e := c.request(ctx, "unbind", device, "", s.Version, &s)
	if e != nil {
		return e
	}
	var d struct {
		Unbound bool `json:"unbound"`
	}
	if json.Unmarshal(r, &d) != nil || !d.Unbound {
		return errors.New("解绑未确认")
	}
	return nil
}

// Maintain fails closed on the first failed heartbeat/renewal. Call only after
// initial Activate succeeds; the caller stops its own workload on a non-nil error.
func (c *Client) Maintain(ctx context.Context, s Session, card, device string) error {
	return c.maintain(ctx, s, card, device, time.Minute)
}

func (c *Client) maintain(ctx context.Context, s Session, card, device string, interval time.Duration) error {
	for {
		remaining := time.Until(time.Unix(s.ExpiresAt, 0))
		if remaining <= 0 {
			return errors.New("授权会话已过期")
		}
		delay := interval
		if remaining < delay {
			delay = remaining
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
		if time.Now().Unix() >= s.ExpiresAt {
			return errors.New("授权会话已过期")
		}
		if time.Until(time.Unix(s.ExpiresAt, 0)) < 2*time.Minute {
			next, e := c.Activate(ctx, card, device)
			if e != nil {
				return e
			}
			s = next
		} else if e := c.Heartbeat(ctx, s, device); e != nil {
			return e
		}
	}
}

// CheckConnection sends only the public config action. No card, fingerprint,
// DPAPI credential, challenge enrollment or protected work is accessed.
func (c *Client) CheckConnection(ctx context.Context) error {
	raw, e := c.request(ctx, "config", "", "", 1, nil)
	if e != nil {
		return e
	}
	var config struct {
		Version int `json:"key_version"`
	}
	if json.Unmarshal(raw, &config) != nil || config.Version < 1 || config.Version > 999999999 {
		return startupdiag.Wrap(startupdiag.LicenseConfig, errors.New("invalid protocol version"))
	}
	return nil
}
