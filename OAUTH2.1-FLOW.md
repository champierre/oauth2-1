# OAuth 2.1 フロー図解説

このドキュメントでは、OAuth 2.1の認証フローを視覚的に解説します。

## OAuth 2.1 認証フロー全体図

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   ユーザー      │    │ クライアント     │    │ 認可サーバー    │
│   (ブラウザ)    │    │ アプリケーション │    │ (Auth Server)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         │                        │                        │
    1. アクセス                   │                        │
         │────────────────────────>│                        │
         │                        │                        │
         │                   2. PKCE生成                   │
         │                    code_verifier                │
         │                    code_challenge               │
         │                        │                        │
         │  3. 認可リクエスト      │                        │
         │    +code_challenge      │                        │
         │<───────────────────────│                        │
         │                        │                        │
         │              4. 認可リクエスト転送               │
         │──────────────────────────────────────────────>│
         │                        │                        │
         │              5. ユーザー認証・認可画面          │
         │<──────────────────────────────────────────────│
         │                        │                        │
    6. 認可許可                   │                        │
         │──────────────────────────────────────────────>│
         │                        │                        │
         │      7. 認可コード + state                     │
         │<──────────────────────────────────────────────│
         │                        │                        │
         │   8. コールバック       │                        │
         │    +認可コード          │                        │
         │────────────────────────>│                        │
         │                        │                        │
         │                        │  9. トークン交換リクエスト│
         │                        │     +code_verifier      │
         │                        │────────────────────────>│
         │                        │                        │
         │                        │ 10. PKCE検証 + トークン発行│
         │                        │<────────────────────────│
         │                        │                        │
         │  11. 成功画面表示       │                        │
         │<───────────────────────│                        │
         │                        │                        │
```

## ステップ詳細解説

### 🔄 Step 1-2: OAuth フロー開始とPKCE生成

```
ユーザー                     クライアント
   │                            │
   │ 1. "OAuth認証開始"クリック  │
   │──────────────────────────>│
   │                            │ 2. PKCE パラメータ生成
   │                            │    code_verifier = random(32bytes)
   │                            │    code_challenge = SHA256(code_verifier)
   │                            │
```

**ここで重要なのは：**
- `code_verifier`: 43-128文字のランダム文字列
- `code_challenge`: code_verifierのSHA256ハッシュをBase64URL エンコード
- この2つがPKCE (Proof Key for Code Exchange) の核心

### 🔐 Step 3-4: 認可リクエスト

```
ユーザー                     クライアント                 認可サーバー
   │                            │                            │
   │ 3. リダイレクト指示        │                            │
   │<───────────────────────── │                            │
   │                            │                            │
   │ 4. 認可エンドポイントへアクセス                         │
   │──────────────────────────────────────────────────────>│
   │                            │                            │
```

**リクエストパラメータ：**
```
GET /authorize?
  response_type=code&
  client_id=demo-client&
  redirect_uri=http://localhost:3000/callback&
  scope=read&
  state=abc123xyz&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

### ✅ Step 5-6: ユーザー認証と認可

```
ユーザー                                              認可サーバー
   │                                                      │
   │ 5. 認可画面表示                                      │
   │    ┌─────────────────────────────┐                 │
   │    │ OAuth 2.1 Authorization     │<─────────────────│
   │    │                             │                  │
   │    │ Client: Demo App            │                  │
   │    │ Scope: read                 │                  │
   │    │                             │                  │
   │    │ [Approve] [Deny]            │                  │
   │    └─────────────────────────────┘                 │
   │                                                      │
   │ 6. "Approve" クリック                               │
   │────────────────────────────────────────────────────>│
   │                                                      │
```

### 🔁 Step 7-8: 認可コード発行とコールバック

```
ユーザー                     クライアント                 認可サーバー
   │                            │                            │
   │ 7. 認可コード付きリダイレクト                          │
   │<──────────────────────────────────────────────────────│
   │                            │                            │
   │ 8. コールバックURL アクセス │                            │
   │──────────────────────────>│                            │
   │                            │                            │
```

**コールバックURL例：**
```
http://localhost:3000/callback?
  code=SplxlOBeZQQYbYS6WxSbIA&
  state=abc123xyz
```

### 🔑 Step 9-10: トークン交換 (最重要)

```
クライアント                                               認可サーバー
     │                                                          │
     │ 9. トークン交換リクエスト                               │
     │────────────────────────────────────────────────────────>│
     │                                                          │
     │                                            10. PKCE検証  │
     │                                               │          │
     │                                               ▼          │
     │                                    received_challenge =  │
     │                                    SHA256(code_verifier) │
     │                                               │          │
     │                                               ▼          │
     │                                    original_challenge == │
     │                                    received_challenge?   │
     │                                               │          │
     │                                               ▼ YES      │
     │                                       アクセストークン発行│
     │<────────────────────────────────────────────────────────│
     │                                                          │
```

**トークン交換リクエスト：**
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=SplxlOBeZQQYbYS6WxSbIA&
redirect_uri=http://localhost:3000/callback&
client_id=demo-client&
client_secret=demo-secret&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

**レスポンス：**
```json
{
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read"
}
```

## 🛡️ OAuth 2.1 セキュリティ特徴

### PKCE (Proof Key for Code Exchange)

```
┌─────────────────────────────────────────────────────────┐
│                    PKCE の仕組み                        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. code_verifier 生成 (クライアント)                   │
│     ├─ ランダム文字列 (43-128文字)                      │
│     └─ 例: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" │
│                                                         │
│  2. code_challenge 生成 (クライアント)                  │
│     ├─ SHA256(code_verifier)                            │
│     └─ Base64URL エンコード                             │
│                                                         │
│  3. 認可リクエスト時                                    │
│     └─ code_challenge を送信                            │
│                                                         │
│  4. トークン交換時                                      │
│     ├─ code_verifier を送信                             │
│     └─ サーバーがSHA256で検証                           │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### State パラメータによるCSRF防止

```
┌─────────────────────────────────────────────────────────┐
│                  State の役割                           │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. ランダムなstate値生成 (クライアント)                │
│     └─ 例: "abc123xyz789"                               │
│                                                         │
│  2. 認可リクエストにstate追加                           │
│     └─ GET /authorize?...&state=abc123xyz789            │
│                                                         │
│  3. 認可サーバーがstateをそのまま返す                   │
│     └─ /callback?code=...&state=abc123xyz789            │
│                                                         │
│  4. クライアントがstate値を検証                         │
│     ├─ 送信した値と一致？ → OK                          │
│     └─ 一致しない → CSRF攻撃の可能性                     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## 📊 OAuth 2.0 vs OAuth 2.1 比較

| 項目 | OAuth 2.0 | OAuth 2.1 |
|------|-----------|-----------|
| **PKCE** | オプション | **必須** |
| **Implicit Grant** | 利用可能 | **廃止** |
| **Password Grant** | 利用可能 | **廃止** |
| **Bearer Token Usage** | RFC 6750 | **RFC 6750 + セキュリティ強化** |
| **Redirect URI** | 部分一致OK | **完全一致必須** |
| **State Parameter** | 推奨 | **強く推奨** |

## 🔍 実装のポイント

### 1. PKCE実装

```javascript
// ✅ 正しいPKCE実装
function generatePKCE() {
  const codeVerifier = base64url(crypto.randomBytes(32));
  const codeChallenge = base64url(sha256(codeVerifier));
  return { codeVerifier, codeChallenge };
}
```

### 2. セキュアなState生成

```javascript
// ✅ 正しいState実装
function generateState() {
  return base64url(crypto.randomBytes(32));
}
```

### 3. トークン検証

```javascript
// ✅ 正しいPKCE検証
function verifyPKCE(codeVerifier, storedChallenge) {
  const computedChallenge = base64url(sha256(codeVerifier));
  return computedChallenge === storedChallenge;
}
```

## ⚠️ よくある実装ミス

### ❌ 間違ったPKCE実装

```javascript
// ❌ 固定値を使用 (危険)
const codeVerifier = "fixed-string";

// ❌ 短すぎるランダム値
const codeVerifier = base64url(crypto.randomBytes(8)); // 8bytesは短すぎ

// ❌ MD5を使用 (SHA256が必須)
const codeChallenge = md5(codeVerifier);
```

### ❌ State検証の漏れ

```javascript
// ❌ State検証なし
app.get('/callback', (req, res) => {
  const { code } = req.query;
  // stateの検証をしていない！
  exchangeCodeForToken(code);
});
```

## 🎯 このサンプルでの実装確認方法

1. **ブラウザ開発者ツールでネットワークタブを開く**
2. **OAuth フローを開始**
3. **各リクエストのパラメータを確認：**
   - 認可リクエスト: `code_challenge`, `state`
   - トークン交換: `code_verifier`
   - レスポンス: `access_token`

## 📚 参考資料

- [OAuth 2.1 Specification (Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [RFC 7636: PKCE](https://tools.ietf.org/html/rfc7636)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)