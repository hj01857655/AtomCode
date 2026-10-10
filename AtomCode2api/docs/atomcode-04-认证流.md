# AtomCode 逆向 04：认证流

> 日期：2026-09-30（**2026-10-09 实测刷新成功**）
> 依赖：[01-recon.md](atomcode-01-侦察与架构.md) 的服务面总览
> 平台认证基址：`https://acs.atomgit.com`

## OAuth 登录

登录（CLI 内 `atomcode login` / TUI `/login`）：
`/auth/login` 发起 → 浏览器授权 → 轮询 `/auth/check` → `GET /auth/token?state=<s>` 换 token。
端点常量见 `crates/atomcode-auth/src/oauth.rs:36-53`。

## Token 刷新（网关 401 自愈的关键，2026-10-09 实测成功）

```
POST https://acs.atomgit.com/oauth/refresh
content-type: application/json
{"refresh_token": "<RT>"}
→ 200 {"access_token":"<新7天token>", "token_type":"Bearer", "expires_in":604800,
       "refresh_token":"<新RT>", "user":{...}}
```

注意 **RT 轮换**：每次刷新返回新 refresh_token，旧值作废，网关必须原子回写。
`expires_in=604800`（7 天）；`auth.toml` 的 `created_at` 为 unix 秒，可推算过期。

## user_id 提取

`user_id` 不再是签名输入（签名已绕开，见 [03-data-plane.md](atomcode-03-数据面与UA门.md)），
仅作账号身份标识。可从 `auth.toml` 的 `[user] id` 字段直接读，或从 refresh_token JWT
payload 的 `user_profile` 字段解出，无需调 API。
