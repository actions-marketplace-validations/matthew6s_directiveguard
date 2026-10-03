# Cloud launch checklist

The code is a deployable MVP, but accepting production payments requires operational setup outside this repository.

## Required before public launch

- Deploy behind HTTPS with `DIRECTIVEGUARD_BASE_URL` set to the exact public origin.
- Store session, GitHub, and Stripe secrets in the hosting provider's secret manager.
- Create the GitHub OAuth App and verify its callback URL.
- Create the $29/month Stripe Team price and configure the three webhook events documented in [cloud.md](cloud.md).
- Enable Stripe tax, receipts, cancellation behavior, and the customer portal settings appropriate to the business.
- Publish reviewed Terms of Service, Privacy Policy, refund terms, and a support contact. The repository does not provide legal advice or jurisdiction-specific documents.
- Configure encrypted database backups and test restoration.
- Monitor `/healthz`, error logs, disk use, webhook failures, and expiring credentials.
- Establish a process for account deletion, data export, and security incident response.
- Run a security review against the deployed origin before inviting users.

## Initial deployment boundary

The SQLite deployment is intended for one application instance with durable storage. Do not run multiple replicas against a shared SQLite file. Move the storage implementation to PostgreSQL before horizontal scaling.

Repository source is scanned in the user's CI environment. Cloud receives finding metadata, file paths, commit and branch identifiers, and GitHub account metadata; disclose that clearly in the final privacy policy.
