use hyper::HeaderMap;
use hyper::header::{HeaderName, USER_AGENT};
use serde::de::IntoDeserializer;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use tracing::debug;

const SEC_CH_UA: HeaderName = HeaderName::from_static("sec-ch-ua");
const SEC_CH_UA_PLATFORM: HeaderName = HeaderName::from_static("sec-ch-ua-platform");

// https://wicg.github.io/ua-client-hints/#sec-ch-ua-platform
#[derive(Serialize, Deserialize, Copy, Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub enum Platform {
    Android,
    #[serde(alias = "Chrome OS")]
    ChromeOS,
    Fuchsia,
    #[serde(alias = "iOS")]
    IOS,
    Linux,
    #[serde(alias = "macOS")]
    MacOS,
    Windows,
    Unknown,
}

#[derive(Serialize, Deserialize)]
pub struct BrowserInfo {
    pub platform: Platform,
    pub brand: Cow<'static, str>,
}

impl Default for BrowserInfo {
    fn default() -> Self {
        Self {
            platform: Platform::Unknown,
            brand: Cow::Borrowed("Unknown"),
        }
    }
}

pub fn browser_info(headers: &HeaderMap) -> BrowserInfo {
    let platform = headers
        .get(SEC_CH_UA_PLATFORM)
        .and_then(|it| it.to_str().ok())
        .map(platform_from_sec_ua_platform)
        .or_else(|| {
            headers
                .get(USER_AGENT)
                .and_then(|it| it.to_str().ok())
                .map(platform_from_user_agent)
        })
        .unwrap_or(Platform::Unknown);
    let brand = headers
        .get(SEC_CH_UA)
        .and_then(|it| it.to_str().ok())
        .map(brand_from_sec_ua)
        .or_else(|| {
            headers
                .get(USER_AGENT)
                .and_then(|it| it.to_str().ok())
                .map(|it| brand_from_user_agent(it, platform))
        })
        .unwrap_or(Cow::Borrowed("Unknown"));
    BrowserInfo { platform, brand }
}

fn platform_from_sec_ua_platform(sec_ua_platform_value: &str) -> Platform {
    if sec_ua_platform_value.len() < 3 {
        return Platform::Unknown;
    }
    let len = sec_ua_platform_value.len();
    if &sec_ua_platform_value[..1] != "\"" || &sec_ua_platform_value[len - 1..] != "\"" {
        return Platform::Unknown;
    }
    let sec_ua_platform_value = &sec_ua_platform_value[1..len - 1];
    let result: Result<_, serde_json::Error> =
        Platform::deserialize(sec_ua_platform_value.into_deserializer());
    result
        .map_err(|err| {
            debug!("{err:?}");
            err
        })
        .unwrap_or(Platform::Unknown)
}

fn brand_from_sec_ua(sec_ua_value: &str) -> Cow<'static, str> {
    let brands = sec_ua_value
        .split(',')
        .filter_map(|it| {
            let mut iter = it.trim().split(';');
            let first = iter.next()?;
            iter.next()?;
            let len = first.len();
            if len < 3 {
                return None;
            }
            if &first[..1] != "\"" || &first[len - 1..] != "\"" {
                return None;
            }
            let first = first[1..len - 1].trim();
            if first.contains("Not") && first.contains("Brand") {
                return None;
            }
            Some(first)
        })
        .collect::<Vec<_>>();
    if brands.is_empty() {
        return Cow::Borrowed("Unknown");
    }
    let brand = if brands.len() == 1 {
        brands[0]
    } else {
        brands
            .into_iter()
            .rev()
            .find(|&it| it != "Chromium")
            .unwrap()
    };
    if brand.contains("Chrome") {
        Cow::Borrowed("Chrome")
    } else if brand.contains("Edge") {
        Cow::Borrowed("Edge")
    } else if brand.contains("Opera") {
        Cow::Borrowed("Opera")
    } else if brand.contains("Vivaldi") {
        Cow::Borrowed("Samsung Internet")
    } else if brand.contains("Firefox") {
        Cow::Borrowed("Firefox")
    } else if brand.contains("Safari") {
        Cow::Borrowed("Safari")
    } else {
        Cow::Owned(brand.to_string())
    }
}

fn platform_from_user_agent(user_agent_value: &str) -> Platform {
    if let Some(unprefixed) = user_agent_value.strip_prefix("Mozilla/5.0 (") {
        if let Some(comment) = unprefixed.split(')').next() {
            if comment.contains("Android") {
                Platform::Android
            } else if comment.contains("iPhone") || comment.contains("iPad") {
                Platform::IOS
            } else if comment.contains("Windows") {
                Platform::Windows
            } else if comment.contains("Macintosh") {
                Platform::MacOS
            } else if comment.contains("CrOS") {
                Platform::ChromeOS
            } else if comment.contains("Fuchsia") {
                Platform::Fuchsia
            } else if comment.contains("X11") {
                Platform::Linux
            } else {
                Platform::Unknown
            }
        } else {
            Platform::Unknown
        }
    } else {
        Platform::Unknown
    }
}

fn brand_from_user_agent(user_agent_value: &str, platform: Platform) -> Cow<'static, str> {
    if user_agent_value.contains("Firefox") {
        Cow::Borrowed("Firefox")
    } else {
        match platform {
            Platform::IOS | Platform::ChromeOS => Cow::Borrowed("Safari"),
            _ => Cow::Borrowed("Unknown"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_from_sec_ua_platform() {
        assert_eq!(
            Platform::Android,
            platform_from_sec_ua_platform("\"Android\"")
        );
        assert_eq!(
            Platform::Windows,
            platform_from_sec_ua_platform("\"Windows\"")
        );
        assert_eq!(Platform::IOS, platform_from_sec_ua_platform("\"iOS\""));
        assert_eq!(Platform::MacOS, platform_from_sec_ua_platform("\"macOS\""));
        assert_eq!(
            Platform::ChromeOS,
            platform_from_sec_ua_platform("\"Chrome OS\"")
        );
    }

    #[test]
    fn test_brand_from_sec_ua() {
        assert_eq!(
            "Chrome",
            brand_from_sec_ua(
                r#"" Not A;Brand";v="99", "Chromium";v="100", "Google Chrome";v="100""#,
            )
            .as_ref()
        );
        assert_eq!(
            "Chrome",
            brand_from_sec_ua(
                r#""Chromium"; v="122", "Not(A:Brand"; v="24", "Google Chrome"; v="122""#,
            )
            .as_ref()
        );
        assert_eq!(
            "Chrome",
            brand_from_sec_ua(
                r#""Chromium";v="115.0.0.0", "Google Chrome";v="115.0.0.0", "Not-A.Brand";v="99""#,
            )
            .as_ref()
        );
        assert_eq!(
            "Opera",
            brand_from_sec_ua(r#""Opera GX";v="109", "Not:A-Brand";v="8", "Chromium";v="123""#,)
                .as_ref()
        );
        assert_eq!(
            "Samsung Internet",
            brand_from_sec_ua(
                r#""Samsung Internet";v="24.0", "Chromium";v="117", "Not;A=Brand";v="8""#,
            )
            .as_ref()
        );
        assert_eq!("iOS", brand_from_sec_ua(r#""iOS";v="15.2.1""#,));
    }

    #[test]
    fn test_platform_from_user_agent() {
        assert_eq!(
            Platform::Windows,
            platform_from_user_agent(
                r#"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"#
            )
        );
        assert_eq!(
            Platform::MacOS,
            platform_from_user_agent(
                r#"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"#
            )
        );
        assert_eq!(
            Platform::Linux,
            platform_from_user_agent(
                r#"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"#
            )
        );
        assert_eq!(
            Platform::IOS,
            platform_from_user_agent(
                r#"Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/138.0.7204.56 Mobile/15E148 Safari/604.1"#
            )
        );
        assert_eq!(
            Platform::IOS,
            platform_from_user_agent(
                r#"Mozilla/5.0 (iPad; CPU OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/138.0.7204.56 Mobile/15E148 Safari/604.1"#
            )
        );
        assert_eq!(
            Platform::Android,
            platform_from_user_agent(
                r#"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.7151.117 Mobile Safari/537.36"#
            )
        );
        assert_eq!(
            Platform::ChromeOS,
            platform_from_user_agent(
                r#"Mozilla/5.0 (X11; CrOS armv7l 16181.61.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.198 Safari/537.36"#
            )
        );
    }
}
