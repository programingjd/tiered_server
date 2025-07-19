pub mod action;

use crate::email::Email;
use crate::handler::static_handler;
use crate::prefix::API_PATH_PREFIX;
use crate::store::Snapshot;
use crate::totp::action::Action;
use crate::user::User;
use base64_simd::URL_SAFE_NO_PAD;
use minijinja::Environment;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::str::from_utf8;
use std::sync::Arc;
use std::time::SystemTime;
use totp_rfc6238::high_level::TotpBuilder;
use tracing::warn;

#[derive(Serialize)]
struct TemplateData<'a> {
    user: &'a User,
    code: &'a str,
    #[serde(flatten)]
    action: &'a Action,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Totp {
    pub(crate) secret: String,
    pub(crate) timestamp: u32,
    pub(crate) retries: u8,
    pub(crate) action: Action,
}

const MAX_UNEXPIRED_REQUESTS_BEFORE_BAN: u8 = 10;
const MAX_RETRIES: u8 = 4;

impl Totp {
    pub(crate) async fn send(self, user: &User) -> Option<()> {
        let generator = TotpBuilder::default()
            .set_digit(8)
            .unwrap()
            .set_step(self.action.validity_duration().unwrap_or(30) as u64)
            .ok()?;
        let generator = generator.build();
        let secret = URL_SAFE_NO_PAD.decode_to_vec(self.secret.as_bytes()).ok()?;
        let code = generator.get_code(&secret);
        let (subject, template_name) = self.action.email_template();
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
                match environment.add_template("totp", jinja) {
                    Ok(()) => environment.get_template("totp"),
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
                        code: code.as_str(),
                        action: &self.action,
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
            Email::send(self.action.email(), subject, html_body.as_str()).await
        } else {
            println!("\x1b[34;49;4m{code}\x1b[0m");
            Some(())
        }
    }

    pub(crate) async fn create(
        user: &User,
        action: Action,
        snapshot: &Arc<Snapshot>,
    ) -> Option<Self> {
        let mut random = [0u8; 32];
        SystemRandom::new().fill(&mut random).unwrap();
        let secret = URL_SAFE_NO_PAD.encode_to_string(random);
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let id = format!("rng/{}/{}", &user.id, action.id());
        let mut totp = Self {
            secret,
            timestamp,
            retries: 0,
            action,
        };
        if let Some(count) = Self::remove_expired_and_count(timestamp, snapshot, &user.id).await {
            if count > MAX_UNEXPIRED_REQUESTS_BEFORE_BAN {
                Self::remove_all(snapshot, &user.id).await;
                totp.timestamp = 0;
            }
        }
        Snapshot::set_and_wait_for_update(&id, &totp).await?;
        Some(totp)
    }

    pub(crate) fn is_valid(&self) -> bool {
        if self.retries > MAX_RETRIES {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        if self.timestamp > now {
            return false;
        }
        let elapsed = now - self.timestamp;
        if let Some(duration) = self.action.validity_duration() {
            return elapsed < duration;
        }
        true
    }

    pub(crate) fn verify(&self, code: &str) -> bool {
        let generator = TotpBuilder::default()
            .set_digit(8)
            .unwrap()
            .set_step(self.action.validity_duration().unwrap_or(30) as u64);
        if generator.is_err() {
            return false;
        }
        let generator = generator.unwrap().build();
        let secret = URL_SAFE_NO_PAD.decode_to_vec(self.secret.as_bytes());
        if secret.is_err() {
            return false;
        }
        let secret = secret.unwrap();
        generator
            .get_code_window(&secret, -1..=1)
            .map(|it| it.iter().any(|c| c == code))
            .unwrap_or(false)
    }

    async fn remove_all(snapshot: &Arc<Snapshot>, user_id: &str) {
        let _ = Snapshot::delete_and_return_before_update(
            snapshot
                .list::<Totp>(&format!("rng/{user_id}/"))
                .map(|(path, _)| path),
        )
        .await;
    }

    async fn remove_expired_and_count(
        timestamp: u32,
        snapshot: &Arc<Snapshot>,
        user_id: &str,
    ) -> Option<u8> {
        let mut count = 0;
        let paths: Vec<String> = snapshot
            .list::<Totp>(&format!("rng/{user_id}/"))
            .filter_map(|(k, totp)| {
                if let Some(duration) = totp.action.validity_duration() {
                    if totp.retries > MAX_RETRIES || totp.timestamp > timestamp {
                        Some(k.to_string())
                    } else {
                        let elapsed = timestamp - totp.timestamp;
                        if elapsed > duration {
                            Some(k.to_string())
                        } else {
                            count += 1;
                            None
                        }
                    }
                } else {
                    count += 1;
                    None
                }
            })
            .collect::<Vec<_>>();
        Snapshot::delete_and_return_before_update(paths.iter()).await?;
        Some(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::totp::action::EmailUpdate;
    use crate::user::{Email, IdentificationMethod};
    use serde_json::json;

    #[test]
    fn test_template_data_serialization() {
        let template_data = TemplateData {
            user: &User {
                id: "user1".to_string(),
                identification: vec![IdentificationMethod::Email(Email {
                    normalized_address: "test@example.com".to_string(),
                    address: "test@example.com".to_string(),
                })],
                last_name: "Doe".to_string(),
                normalized_last_name: "Doe".to_string(),
                first_name: "John".to_string(),
                normalized_first_name: "John".to_string(),
                date_of_birth: 20000101,
                admin: false,
                metadata: None,
            },
            code: "12345678",
            action: &Action::UpdateEmail(EmailUpdate {
                normalized_old_address: "test@example.com".to_string(),
                normalized_new_address: "new@example.com".to_string(),
                new_address: "new@example.com".to_string(),
            }),
        };
        let expected = json!({
            "user": {
                "id": "user1",
                "identification": [
                    {
                        "type": "email",
                        "address": "test@example.com",
                        "normalized_address": "test@example.com"
                    }
                ],
                "last_name": "Doe",
                "normalized_last_name": "Doe",
                "first_name": "John",
                "normalized_first_name": "John",
                "date_of_birth": 20000101
            },
            "code": "12345678",
            "normalized_old_address": "test@example.com",
            "normalized_new_address": "new@example.com",
            "new_address": "new@example.com",
        });
        assert_eq!(expected, serde_json::to_value(template_data).unwrap());
    }
}
