use crate::env::ConfigurationKey::{
    EmailApiAuthHeader, EmailApiAuthToken, EmailApiEndpoint, EmailSendAddress,
};
use crate::env::secret_value;
use reqwest::Client;
use serde::Serialize;
use std::sync::LazyLock;

#[derive(Serialize)]
pub(crate) struct Email<'a> {
    from: Option<&'static str>,
    to: &'a str,
    subject: &'static str,
    html: &'a str,
}

//noinspection SpellCheckingInspection
static EMAIL_API_ENDPOINT: LazyLock<&'static str> =
    LazyLock::new(|| secret_value(EmailApiEndpoint).unwrap_or("https://smtp.maileroo.com/send"));
//noinspection SpellCheckingInspection
static EMAIL_API_AUTH_HEADER: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailApiAuthHeader));
//noinspection SpellCheckingInspection
static EMAIL_API_AUTH_TOKEN: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailApiAuthToken));
//noinspection SpellCheckingInspection
static EMAIL_SEND_ADDRESS: LazyLock<Option<&'static str>> =
    LazyLock::new(|| secret_value(EmailSendAddress));

impl<'a> Email<'a> {
    pub(crate) async fn send(
        email_address: &'a str,
        subject: &'static str,
        html_body: &'a str,
    ) -> Option<()> {
        let email = Self {
            from: *EMAIL_SEND_ADDRESS,
            to: email_address,
            subject,
            html: html_body,
        };
        let req = Client::new().post(*EMAIL_API_ENDPOINT).json(&email);
        let req = if let Some(auth_header) = *EMAIL_API_AUTH_HEADER {
            if let Some(auth_token) = *EMAIL_API_AUTH_TOKEN {
                req.header(auth_header, auth_token)
            } else {
                req
            }
        } else {
            req
        };
        let resp = req.send().await.ok()?;
        if resp.status().is_success() {
            return Some(());
        }
        None
    }
}
