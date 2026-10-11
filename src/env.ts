/**
 * The bindings a Kukuroo deployment needs.
 *
 * Host Workers extend their own `Env` with this, so a missing binding is a type
 * error at build time rather than a 500 the first time someone enrolls.
 */
export interface KukurooEnv {
  /** KV namespace holding the subscriptions. */
  KUKUROO_SUBS: KVNamespace;

  /**
   * Worker Secret. The ES256 VAPID keypair, as a JWK, PKCS#8, or base64url of
   * the bare 32-byte scalar. Generate once, never rotate, keep an offline copy.
   *
   * Prefer a JWK. It carries the public half too, so KUKUROO_VAPID_PUBLIC
   * becomes unnecessary and the two values cannot drift apart.
   */
  KUKUROO_VAPID_PRIVATE: string;

  /**
   * Optional plain var, not a secret: base64url of the uncompressed P-256 point.
   *
   * Only required when the private key is stored as a bare 32-byte scalar,
   * which does not carry its public half. With a JWK or PKCS#8 the public key
   * is derived, and `GET <prefix>/public-key` serves it to the enrollment page,
   * so there is nothing to configure and nothing to mistype.
   *
   * When it *is* set it is verified against the private key rather than
   * trusted, because a mismatched pair delivers nothing and reports nothing.
   */
  KUKUROO_VAPID_PUBLIC?: string;

  /**
   * Worker Secret. The unnamed bearer token for `POST /push/send`, sent as
   * `Authorization: Bearer <token>`.
   *
   * Optional, because a deployment may use named tokens instead -- and only
   * named ones. Adding it back to a Worker that has only named tokens is the
   * only way to make a bare, unnamed credential work there.
   */
  KUKUROO_SEND_TOKEN?: string;

  /**
   * Worker Secrets. Any number of further send tokens, one per name, where the
   * credential is `Authorization: Bearer <name>.<secret>`: the name `ci` reads
   * the secret `KUKUROO_SEND_TOKEN_CI`, and `mac-mini` reads
   * `KUKUROO_SEND_TOKEN_MAC_MINI`.
   *
   * They cannot be listed here the way the fixed bindings are, because the list
   * is whatever the operator created with `wrangler secret put`. A name is one
   * to 32 characters of `a-z`, `0-9` and interior `-`, matched without regard
   * to case, and a name with no secret of its own answers 401 rather than the
   * 503 above: naming the missing variable would report which names exist to
   * whoever asks.
   */
  // KUKUROO_SEND_TOKEN_<NAME>: string;

  /** Worker Secret. Gate on `POST /push/subscribe`. */
  KUKUROO_INVITE_CODE: string;

  /**
   * Optional. The VAPID `sub` claim: a mailto: or https: URI identifying the
   * sender. Defaults to the push service's own origin, which Apple accepts.
   */
  KUKUROO_VAPID_SUBJECT?: string;

  /**
   * Optional but recommended for mounted deployments: the origin every
   * notification's `navigate` must be on, e.g. `https://push.example.com`.
   *
   * Mounting makes same-origin likely; this makes it enforced. A `navigate`
   * that leaves the origin ejects the user out of the installed web app.
   */
  KUKUROO_NAVIGATE_ORIGIN?: string;

  /**
   * Optional. Comma-separated exact origins whose pages may call
   * `<prefix>/subscribe` and `<prefix>/public-key` from the browser, e.g.
   * "https://www.example.com". Unset, no CORS headers are sent, which is the
   * right default when the enrollment page lives on this Worker's own origin.
   *
   * `<prefix>/send` is never CORS-enabled regardless of this list: the send
   * token is a server secret, and a browser page that holds one is a leak in
   * progress, so that mistake should fail on its first test.
   */
  KUKUROO_ALLOWED_ORIGINS?: string;
}
