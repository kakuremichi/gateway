# kakuremichi（隠れ道）Gateway
## About
kakuremichi の入口ノード。Control と WebSocket で接続し、設定を受信して Agent への WireGuard トンネルを確立する。外部ユーザーからの HTTP/HTTPS リクエストを受け、対応する Agent へプロキシする。

## できること
- Control からの設定更新を受信し、WireGuard ピア（Agent）を動的に追加・更新
- ドメインベースの HTTP リバースプロキシで、WireGuard トンネル経由で Agent へ転送
- Let's Encrypt による自動 SSL 証明書取得・更新（ACME HTTP-01）
- API キーによる認証、WireGuard 鍵の自動生成と永続化（`wireguard.key`）
- 起動時に Public IP を自動取得して Control に登録

## 必要環境
- Go 1.23+
- Linux（WireGuard インターフェース操作に `ip` コマンドを使用）
- Control サーバーが起動済みで API キーを発行できること
- ポート 80/443（HTTP/HTTPS）、51820/UDP（WireGuard）が開放されていること

## クイックスタート
1. `.env.example` をコピーして値を入れる:
   ```bash
   cp .env.example .env
   # CONTROL_URL, API_KEY を設定
   ```
2. 実行:
   ```bash
   go run ./cmd/gateway \
     --control-url=ws://localhost:3001 \
     --api-key=gtw_your_api_key_here
   ```
   - `WIREGUARD_PRIVATE_KEY` を指定しない場合、起動時に `wireguard.key` として生成・保存。
   - 初回に Control から Agent/トンネル設定を受け取ると WireGuard ピアと HTTP プロキシルートが設定される。

### コンフィグ（環境変数/フラグ）

**Control 接続**
- `CONTROL_URL` / `--control-url` : Control への WebSocket URL（例: `ws://localhost:3001`）
- `API_KEY` / `--api-key` : Control で発行したゲートウェイ用 API キー（必須）

**WireGuard**
- `WIREGUARD_PORT` / `--wireguard-port` : WireGuard の UDP ポート（デフォルト: `51820`）
- `WIREGUARD_INTERFACE` / `--wireguard-interface` : WireGuard インターフェース名（デフォルト: `wg0`）
- `WIREGUARD_KEY_FILE` / `--wireguard-key-file` : 秘密鍵ファイルパス（デフォルト: `wireguard.key`）

**HTTP/HTTPS**
- `HTTP_PORT` / `--http-port` : HTTP ポート（デフォルト: `80`）
- `HTTPS_PORT` / `--https-port` : HTTPS ポート（デフォルト: `443`）

**Let's Encrypt (ACME)**
- `ACME_EMAIL` / `--acme-email` : Let's Encrypt 用メールアドレス（設定すると HTTPS 有効化）
- `ACME_STAGING` / `--acme-staging` : ステージング環境を使用（デフォルト: `false`）
- `ACME_CACHE_DIR` / `--acme-cache-dir` : 証明書キャッシュディレクトリ（デフォルト: `./cache/autocert`）

**サーバー設定**
- `PUBLIC_IP` / `--public-ip` : 固定 Public IP（空の場合は自動取得）
- `PUBLIC_IPV4_CHECKER` / `--public-ipv4-checker` : Public IP 取得 URL（デフォルト: `https://sweak.net/ip` ）
- `REGION` / `--region` : Gateway のリージョン識別子（デフォルト: `local`）

## 開発
- Dev Container を推奨
- テスト: `go test ./...`
- ローカルビルド: `go build ./cmd/gateway`
- Docker イメージ:
  ```bash
  docker build -t kakuremichi-gateway .
  ```

## プロジェクト構成
- `cmd/gateway` : エントリポイント
- `internal/config` : フラグ/環境変数ロード
- `internal/ws` : Control との WebSocket クライアント
- `internal/wireguard` : WireGuard インターフェース管理と鍵生成
- `internal/proxy` : HTTP/HTTPS リバースプロキシ（ACME 対応）

## メモ
- WireGuard キーはリポジトリ直下に保存されるため、共有したくない場合は `.gitignore` 等で除外するか、パスを変えて運用してください。
- HTTPS を有効にするには `ACME_EMAIL` に有効なメールアドレスを設定してください（`admin@example.com` 以外）。
- WireGuard インターフェースの操作には root 権限または `CAP_NET_ADMIN` が必要です。
