# Stripe

- Entry points: Checkout/PaymentIntent creation, webhook handlers, refunds, credits and entitlement updates.
- Auth/ownership: derive amount, currency, price and customer from server-side records; verify webhook signature on the raw body.
- Persistence: correlate Stripe event IDs, idempotency keys, transaction boundaries and entitlement state.
- Dangerous bypasses: client amount/price, parsed body before signature verification, replayable events, fulfillment on redirect alone.
- Companions: product/pricing tables, webhook route config, raw-body middleware, queue worker, ledger and tests.
- Negative tests: altered amount, replayed event, duplicate delivery, invalid signature, delayed fulfillment and failed database write.
- False positives: a public checkout identifier is not authority for price; confirm the server lookup before reporting.
- Verification: inspect the declared Stripe SDK version and local webhook middleware/types; use signed test fixtures, never live payments.
