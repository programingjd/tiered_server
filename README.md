### Rust http server with static content and user protected content.

The server is set up so that it doesn't require disk access.

The static content comes from a GitHub repository.<br>
[zip_static_handler](https://crates.io/crates/zip_static_handler) is used for that purpose.<br>
The [project page](https://github.com/programingjd/zip_static_handler) details the conventions for directory indices and
redirects.
Which repository is used is configurable with the environment variables:

- `STATIC_GITHUB_USER`
- `STATIC_GITHUB_REPOSITORY`
- `STATIC_GITHUB_BRANCH`

You can also set up a webhook to notify the server when the content has changed and needs to be updated.
You can do that with a GitHub push webhook (you can use any path, the server ignores it). You need to specify the token
with the variable:

- `STATIC_GITHUB_WEBHOOK_TOKEN`

Part of the static content should include templates for the messages sent for account creation and credentials resets.
You need to specify where those templates are with the variable:

- `TEMPLATE_PATH_PREFIX`

<br>

The server is meant to be behind the Cloudflare CDN.<br>
You need to register the apex domain and its `www` subdomain with Cloudflare, and specify the apex domain with the
variable:

- `DOMAIN_APEX`

There's a built-in firewall that terminates the connections unless they come
from either one of Cloudflare CDN servers or one of the GitHub webook servers for the update webhook.

The server is HTTPS only and the certificate is self-signed.

<br>

You need to specify a prefix for the static content that is scoped to the user and require the user to be logged in,
and you also need to specify the path for the login page.

- `USER_PATH_PREFIX`
- `LOGIN_PATH`

You also need to reserve a prefix for the API, and specify what it is with the variable:

- `API_PATH_PREFIX`

<br>

The user data is stored in an S3 bucket. You need to provide the information needed to access it:

- `S3_REGION`
- `S3_ENDPOINT`
- `S3_BUCKET`
- `S3_ACCESS_KEY`
- `S3_SECRET_KEY`

That content is encrypted so that the information stays safe even if access to the bucket is obtained. You should
specify the encryption parameters with the variables:

- `STORE_ENCRYPTION_KEY`
- `OTP_SIGNING_KEY`
- `IDENTIFICATION_HASH_PREFIX`

<br>

You also need to specify what service to use to send messages to users for registering an account or resetting their
credentials with the variables:

- `EMAIL_API_ENDPOINT`
- `EMAIL_API_AUTH_HEADER`
- `EMAIL_API_AUTH_TOKEN`
- `EMAIL_API_METHOD`
- `EMAIL_API_REQUEST_CONTENT_TYPE`
- `EMAIL_SEND_ADDRESS`
- `EMAIL_NEW_CREDENTIALS_TITLE`
- `EMAIL_NEW_CREDENTIALS_TEMPLATE`

---

S3 object storage

```
/sid/{session_id} -> (user_id,identity_hash,timestamp)
  ...
/otp/{otp_token} -> (user_id,identity_hash,timestamp)
  ...  
/pk/{identity_hash}/{user_id} -> {user}
/pk/{identity_hash}/{user_id}/{passkey} -> {}
  ...
```

### Connection

```mermaid
graph TD;
  A[Request user page] --> B[Session cookie?];
  B -- Yes --> C[Extract username/email] --> D[Still valid?]
  D -- Yes --> J(("<b>Show<br>user page</b>"))
  D -- No --> G
  B -- No --> E["<i>Login page</i><br>Ask for username/email"] --> F[Passkey in db?]
  F -- Yes --> G[Ask for passkey]
  F -- No -->  M[Email OTP bound to username/email]
  M -- Visit --> H[Create and store passkey]
  H --> G
  G -- Success --> K[Session cookie] --> J
  G -- Failure --> N[Reset?]
  N -- Yes --> M
  N -- No --> G
```

Two cookies are used, one for the server and one for javascript:

- `st` (accessible from javascript)<br>
  contains the connection expiration timestamp

- `sid`
  *http-only (not accessible from javascript)*<br>
  contains the session id

Both cookies have the maximum lifespan (400 days) because they don't include any sensitive information.

API requests return `403 FORBIDDEN` if the session id from the `sid` cookie is missing or expired.

For user scoped html pages, the server first checks if the `sid` cookie exists and refers to an
existing session id with user info (but it might be expired).

The page (javascript) should look for the `st` cookie.<br>
If it's expired (or missing), the page should trigger the passkey authorization flow to reconnect
the user. Otherwise, api calls will fail because the connection has expired.

The passkey authorization flow is as follows:

- the page requests the challenge from the server
- the server retrieves the user info from the session id (from the `sid` cookie value).
  if this fails then the server returns an error, otherwise, it returns the challenge.
- ...

