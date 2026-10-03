# DirectiveGuard Cloud

DirectiveGuard Cloud is the hosted layer for teams using the open-source scanner across many repositories. The repository contains a deployable MVP with GitHub OAuth, project API keys, scan history, plan limits, and Stripe subscriptions.

## Free and open source

- Local CLI and GitHub Action
- All core detection rules
- Text, JSON, and SARIF output
- CI severity thresholds
- Community rule contributions

## Included Team features

- Up to 25 projects and 5,000 scan uploads per account each month
- Central scan history without uploading repository source
- Hashed, revocable project API keys
- Stripe Checkout and customer billing portal
- GitHub-authenticated dashboard

## Run locally

1. Copy `.env.example` to a private environment file and generate `DIRECTIVEGUARD_SESSION_SECRET` with `openssl rand -base64 32`.
2. Create a GitHub OAuth App whose callback is `http://localhost:8080/auth/github/callback`.
3. Set `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET`.
4. Start `go run ./cmd/directiveguard-cloud` and open `http://localhost:8080`.

Billing remains disabled until `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, and `STRIPE_TEAM_PRICE_ID` are all configured. Register `/webhooks/stripe` for `checkout.session.completed`, `customer.subscription.updated`, and `customer.subscription.deleted`.

Complete the [launch checklist](launch-checklist.md) before accepting production payments.

For a container deployment:

```sh
docker build -f Cloud.Dockerfile -t directiveguard-cloud .
docker run --read-only --tmpfs /tmp -v directiveguard-data:/data --env-file .env -p 8080:8080 directiveguard-cloud
```

## Upload from CI

```sh
DIRECTIVEGUARD_API_KEY=dg_live_... directiveguard --upload https://cloud.example.com .
```

For the GitHub Action, provide `cloud-url` and store `api-key` in GitHub Actions secrets.

## Next enterprise features

- GitHub organization installation and automatic repository discovery
- Central policy exceptions with owners and expiry dates
- Pull-request annotations and change-aware scans
- SSO, role-based access, audit exports, and private deployment

The hosted product should charge for coordination, history, and organization-wide operations—not for access to basic security findings.
