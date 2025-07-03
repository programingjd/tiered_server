use crate::email::Email;
use crate::handler::static_handler;
use crate::otp::action::Action;
use crate::otp::signature::token_signature;
use crate::prefix::API_PATH_PREFIX;
use crate::store::Snapshot;
use crate::user::{IdentificationMethod, User};
use base64_simd::URL_SAFE_NO_PAD;
use minijinja::Environment;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::from_utf8;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::warn;

pub mod action;
mod endpoints;
pub(crate) mod handler;
mod signature;

const OTP_VALIDITY_DURATION: u32 = 1_200; // 20 mins

#[derive(Serialize)]
struct TemplateData<'a> {
    user: &'a User,
    link_url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none", flatten)]
    value: Option<&'a Value>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Otp {
    id: String,
    user_id: String,
    timestamp: u32,
    action: Action,
    data: Option<Value>,
}

impl Otp {
    pub(crate) async fn send(
        user: &User,
        action: Action,
        value: Option<Value>,
        snapshot: &Arc<Snapshot>,
        server_name: &Arc<String>,
    ) -> Option<()> {
        let email = match &user.identification {
            IdentificationMethod::Email(email) => email.address.as_str(),
            _ => return None,
        };
        let otp = Self::create(user, action, value, snapshot).await?;
        Self::send_otp(user, email, otp, server_name).await
    }

    async fn send_otp(
        user: &User,
        email: &str,
        otp: Self,
        server_name: &Arc<String>,
    ) -> Option<()> {
        let id = otp.id.as_str();
        let signature = token_signature(id).expect("token should be url safe base64 encoded");
        let link_url = format!(
            "https://{server_name}{}otp/{id}.{signature}",
            API_PATH_PREFIX.with_trailing_slash
        );
        let (subject, template_name) = otp.action.email_template();
        let subject = subject?;
        let template_name = template_name?;
        let content = match static_handler()
            .entry(&format!(
                "{}{template_name}",
                API_PATH_PREFIX.with_trailing_slash
            ))
            .and_then(|it| it.content.clone())
        {
            Some(content) => content,
            None => {
                warn!(
                    "missing email template: {}{template_name}",
                    API_PATH_PREFIX.with_trailing_slash
                );
                return None;
            }
        };
        let html_body = match from_utf8(content.as_ref()) {
            Ok(jinja) => {
                let mut environment = Environment::new();
                match environment.add_template("new_credentials", jinja) {
                    Ok(()) => environment.get_template("new_credentials"),
                    Err(err) => {
                        warn!(
                            "invalid template: {}{template_name}:\n{err:?}",
                            API_PATH_PREFIX.with_trailing_slash
                        );
                        return None;
                    }
                }
                .and_then(|template| {
                    template.render(TemplateData {
                        user,
                        link_url: link_url.as_str(),
                        value: otp.data.as_ref(),
                    })
                })
            }
            Err(_) => {
                warn!(
                    "invalid template: {}{template_name}",
                    API_PATH_PREFIX.with_trailing_slash
                );
                return None;
            }
        };
        let html_body = match html_body {
            Ok(html_body) => html_body,
            Err(err) => {
                warn!(
                    "invalid template: {}{template_name}:\n{err:?}",
                    API_PATH_PREFIX.with_trailing_slash
                );
                return None;
            }
        };
        #[cfg(debug_assertions)]
        let send = false;
        #[cfg(not(debug_assertions))]
        let send = true;
        if send {
            Email::send(email, subject, html_body.as_str()).await
        } else {
            println!("\x1b[34;49;4m{link_url}\x1b[0m");
            Some(())
        }
    }

    async fn create(
        user: &User,
        action: Action,
        data: Option<Value>,
        snapshot: &Arc<Snapshot>,
    ) -> Option<Self> {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let mut random = [0u8; 36];
        random[32..].copy_from_slice(timestamp.to_be_bytes().as_slice());
        SystemRandom::new().fill(&mut random[..32]).unwrap();
        let id = URL_SAFE_NO_PAD.encode_to_string(random);
        let key = format!("otp/{id}");
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let otp = Self {
            id,
            user_id: user.id.clone(),
            timestamp: action
                .otp_validity_duration()
                .map(|it| timestamp + it)
                .unwrap_or(0),
            action,
            data,
        };
        let _ = Self::remove_expired(timestamp, snapshot, Some(user.id.as_str())).await;
        Snapshot::set_and_wait_for_update(key.as_str(), &otp).await?;
        Some(otp)
    }

    async fn remove_expired(
        timestamp: u32,
        snapshot: &Arc<Snapshot>,
        user_id: Option<&str>,
    ) -> Option<()> {
        let paths: Vec<String> = snapshot
            .list::<Otp>("opt/")
            .filter_map(|(k, otp)| {
                if otp.timestamp == 0 {
                    if let Some(user_id) = user_id {
                        if otp.user_id == user_id {
                            Some(k.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    let elapsed = timestamp - otp.timestamp;
                    if otp.timestamp > timestamp || elapsed > OTP_VALIDITY_DURATION {
                        Some(k.to_string())
                    } else if let Some(user_id) = user_id {
                        if otp.user_id == user_id {
                            Some(k.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            })
            .collect::<Vec<_>>();
        Snapshot::delete_and_return_before_update(paths.iter()).await
    }
}
