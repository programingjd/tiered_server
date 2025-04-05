use std::borrow::Cow;
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

pub fn normalize_email(email: &str) -> String {
    let trim = email.trim();
    let mut iter = trim.split('@');
    if let Some(local) = iter.next() {
        if let Some(domain) = iter.next() {
            return if domain.as_bytes().eq_ignore_ascii_case(b"gmail.com") {
                if local.contains('.') {
                    format!("{}@{}", local.split('.').collect::<String>(), domain)
                } else {
                    format!("{}@{}", local, domain)
                }
            } else if domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            {
                format!("{}@{}", local, domain)
            } else {
                let domain = domain
                    .split('.')
                    .map(|label| {
                        if label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                            Cow::Borrowed(label)
                        } else {
                            punycode::encode(label)
                                .map(|it| Cow::Owned(format!("xn--{}", it)))
                                .unwrap_or(Cow::Borrowed(label))
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(".");
                format!("{}@{}", local, domain)
            };
        }
    }
    trim.to_string()
}

pub fn normalize_phone_number(_number: &str) -> String {
    todo!()
}

pub fn normalize_first_name(first_name: &str) -> String {
    normalize_name(first_name)
}

pub fn normalize_last_name(last_name: &str) -> String {
    normalize_name(last_name)
}

fn normalize_name(name: &str) -> String {
    name.nfkd()
        .flat_map(|it| match get_general_category(it) {
            GeneralCategory::UppercaseLetter | GeneralCategory::LowercaseLetter => Some(it),
            GeneralCategory::OtherPunctuation if it == '\'' => Some('\''),
            GeneralCategory::FinalPunctuation if it == '’' => Some('\''),
            GeneralCategory::SpaceSeparator => Some(' '),
            GeneralCategory::DashPunctuation => Some('-'),
            _ => None,
        })
        .collect::<String>()
        .trim()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_email() {
        assert_eq!(
            "nobody@test.xn--cu8h.com",
            normalize_email("nobody@test.📦.com")
        );
        assert_eq!("nobody@gmail.com", normalize_email("no.body@gmail.com"));
    }

    #[test]
    fn test_normalize_name() {
        assert_eq!("ecalu", normalize_name("Éçàlü "));
    }
}
