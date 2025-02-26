#

object storage

```
/
  otp
    email
      {encrypted_email_hash_1}
        {otp_token_1}
      {encrypted_email_hash_2}
      {encrypted_email_hash_3}
    sms
      {encrypted_sms_hash_1}
  pk
    {encrypted_email_hash_2}
      {pk_1}
```

```mermaid
graph TD;
  A[Request user page] --> B[Session cookie?];
  B -- Yes --> C[Extract username/email] --> D[Still valid?]
  D -- Yes --> J(("<b>Show<br>user page</b>"))
  D -- No --> G
  B -- No --> E[Ask for username/email] --> F[Passkey in db?]
  F -- Yes --> G[Ask for passkey]
  F -- No -->  M[Email OTP bound to username/email]
  M -- Visit --> H[Create and store passkey]
  H --> G
  G -- Success --> K[Session cookie] --> J
  G -- Failure --> N[Reset?]
  N -- Yes --> M
  N -- No --> G
```
