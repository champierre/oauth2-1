# OAuth 2.1 Sample Implementation

このプロジェクトは、OAuth 2.1の完全な実装サンプルです。認可サーバーとクライアントアプリケーションの両方が含まれています。

## OAuth 2.1の主な特徴

OAuth 2.1は、OAuth 2.0の改良版で、以下のセキュリティ強化が含まれています：

- **PKCE (Proof Key for Code Exchange) が必須**: すべてのOAuthフローでPKCEが要求されます
- **Implicit Grantの廃止**: セキュリティリスクの高いImplicit Grantは削除されています
- **より厳格なリダイレクトURI検証**: 完全一致が必要です
- **State parameterの使用推奨**: CSRF攻撃を防ぐためのState parameterが重要視されています

## プロジェクト構成

```
oauth2-1/
├── src/
│   ├── auth-server/     # OAuth 2.1 認可サーバー
│   │   └── server.js
│   └── client/          # OAuth 2.1 クライアントアプリケーション
│       └── client.js
├── package.json
└── README.md
```

## 実装されているエンドポイント

### 認可サーバー (http://localhost:3001)

- `GET /authorize` - 認可エンドポイント（PKCE対応）
- `POST /authorize/approve` - 認可承認処理
- `POST /token` - トークンエンドポイント（PKCE検証付き）
- `GET /userinfo` - ユーザー情報エンドポイント
- `GET /.well-known/oauth-authorization-server` - 認可サーバーメタデータ

### クライアントアプリケーション (http://localhost:3000)

- `GET /` - メインページ（OAuth フロー開始）
- `POST /start-oauth` - OAuth フロー開始（PKCE生成）
- `GET /callback` - OAuth コールバック処理

## セットアップと実行

### 1. 依存関係のインストール

```bash
npm install
```

### 2. アプリケーションの起動

#### 両方のサーバーを同時に起動する場合：
```bash
npm start
```

#### 個別に起動する場合：

認可サーバーを起動：
```bash
npm run start:auth-server
```

クライアントアプリケーションを起動（別ターミナル）：
```bash
npm run start:client
```

### 3. ブラウザでアクセス

1. http://localhost:3000 にアクセス
2. "Start OAuth 2.1 Flow" ボタンをクリック
3. 認可サーバーでの認可画面で "Approve" をクリック
4. アクセストークンとユーザー情報が表示される

## OAuth 2.1 フローの詳細

### 1. PKCE パラメータ生成
```javascript
// Code Verifier (ランダム文字列)
const codeVerifier = base64url(crypto.randomBytes(32));

// Code Challenge (Code VerifierのSHA256ハッシュ)
const codeChallenge = base64url(sha256(codeVerifier));
```

### 2. 認可リクエスト
```
GET /authorize?
  response_type=code&
  client_id=demo-client&
  redirect_uri=http://localhost:3000/callback&
  scope=read&
  state={random_state}&
  code_challenge={code_challenge}&
  code_challenge_method=S256
```

### 3. トークン交換
```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code={authorization_code}&
redirect_uri=http://localhost:3000/callback&
client_id=demo-client&
client_secret=demo-secret&
code_verifier={code_verifier}
```

## セキュリティ機能

- **PKCE**: すべての認可コード交換でCode VerifierとChallengeを使用
- **State Parameter**: CSRF攻撃防止のためのランダムなstate値
- **短期間のトークン**: アクセストークンは1時間で期限切れ
- **厳密なリダイレクトURI**: 登録されたURIとの完全一致チェック
- **認可コードの単回使用**: 認可コードは一度使用されると無効化

## 設定

### クライアント設定
- Client ID: `demo-client`
- Client Secret: `demo-secret`
- Redirect URI: `http://localhost:3000/callback`

### サポートされているスコープ
- `read`: 読み取り権限
- `write`: 書き込み権限

## トラブルシューティング

### よくある問題

1. **"PKCE is required"エラー**
   - OAuth 2.1ではPKCEが必須です。code_challengeとcode_challenge_methodパラメータが必要です。

2. **"invalid_redirect_uri"エラー**
   - リダイレクトURIが正確に一致する必要があります。URLの最後のスラッシュにも注意してください。

3. **"invalid_grant"エラー**
   - 認可コードが期限切れ（10分）または既に使用済みの可能性があります。

### デバッグ情報

サーバーコンソールでHTTPリクエスト/レスポンスの詳細を確認できます。

## ライセンス

MIT License
