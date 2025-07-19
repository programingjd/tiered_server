use crate::env::ConfigurationKey::{
    EmailApiAuthHeader, EmailApiAuthToken, EmailApiEndpoint, EmailApiMethod,
    EmailApiRequestContentType, EmailSendAddress,
};
use crate::env::secret_value;
use crate::server::DOMAIN_TITLE;
use reqwest::Client;
use reqwest::multipart::Form;
use serde::Serialize;
use std::sync::LazyLock;
use tracing::warn;

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
//noinspection SpellCheckingInspection
static EMAIL_API_METHOD: LazyLock<&'static str> =
    LazyLock::new(|| secret_value(EmailApiMethod).unwrap_or("POST"));
//noinspection SpellCheckingInspection
static EMAIL_API_REQUEST_CONTENT_TYPE: LazyLock<&'static str> =
    LazyLock::new(|| secret_value(EmailApiRequestContentType).unwrap_or("multipart/form-data"));

impl<'a> Email<'a> {
    pub(crate) async fn send(
        email_address: &'a str,
        subject: &'static str,
        html_body: &'a str,
    ) -> Option<()> {
        let from = *EMAIL_SEND_ADDRESS;
        let req = Client::new();
        let req = match *EMAIL_API_METHOD {
            "POST" => req.post(*EMAIL_API_ENDPOINT),
            "PUT" => req.put(*EMAIL_API_ENDPOINT),
            _ => return None,
        };
        let req = match *EMAIL_API_REQUEST_CONTENT_TYPE {
            "multipart/form-data" => {
                let form = Form::new();
                let form = if let Some(from) = from {
                    let display_name = *DOMAIN_TITLE;
                    form.text("from", format!("\"{display_name}\" <{from}>"))
                } else {
                    form
                }
                .text("to", email_address.to_string())
                .text("subject", subject)
                .text("html", html_body.to_string());
                req.multipart(form)
            }
            "application/json" => {
                let email = Self {
                    from,
                    to: email_address,
                    subject,
                    html: html_body,
                };
                req.json(&email)
            }
            _ => return None,
        };
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
        if let Ok(text) = resp.text().await {
            warn!("{text}");
        }
        None
    }
}
