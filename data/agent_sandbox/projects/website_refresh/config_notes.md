# Website refresh - config notes

- Payments webhook: signed. Signing key name: billing-webhook-signing-key
  (the key material lives in the secret manager, not here).
- CDN cache TTL: 300 seconds.
- Feature flag for the new hero banner: hero_v2_enabled.
