use crate::env::ConfigurationKey::DefaultCountryCode;
use crate::env::secret_value;
use std::borrow::Cow;
use std::sync::LazyLock;
use unicode_general_category::{GeneralCategory, get_general_category};
use unicode_normalization::UnicodeNormalization;

pub static DEFAULT_COUNTRY_CODE: LazyLock<u16> = LazyLock::new(|| {
    secret_value(DefaultCountryCode)
        .and_then(|it| it.parse::<u16>().ok())
        .unwrap_or(33)
});

pub fn normalize_email(email: &str) -> String {
    let trim = email.trim();
    let mut iter = trim.split('@');
    if let Some(local) = iter.next() {
        if let Some(domain) = iter.next() {
            return if domain.as_bytes().eq_ignore_ascii_case(b"gmail.com") {
                if local.contains('.') {
                    format!("{}@{}", local.split('.').collect::<String>(), domain)
                } else {
                    format!("{local}@{domain}")
                }
            } else if domain
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            {
                format!("{local}@{domain}")
            } else {
                let domain = domain
                    .split('.')
                    .map(|label| {
                        if label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                            Cow::Borrowed(label)
                        } else {
                            punycode::encode(label)
                                .map(|it| Cow::Owned(format!("xn--{it}")))
                                .unwrap_or(Cow::Borrowed(label))
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(".");
                format!("{local}@{domain}")
            };
        }
    }
    trim.to_string()
}

pub fn normalize_phone_number(number: &str, default_country_code: u16) -> String {
    // https://en.wikipedia.org/wiki/List_of_telephone_country_codes
    // trim leading 0 after country code except for italy (39)
    let trimmed_number = number.trim();
    if !trimmed_number.starts_with('+') {
        let filtered_number = trimmed_number
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect::<String>();
        if filtered_number.starts_with('0') && default_country_code != 39 {
            format!("+{default_country_code}{}", &filtered_number[1..])
        } else {
            format!("+{default_country_code}{filtered_number}")
        }
    } else {
        let filtered_number = trimmed_number
            .chars()
            .enumerate()
            .filter_map(|(i, c)| {
                if i == 0 || c.is_ascii_digit() {
                    Some(c)
                } else {
                    None
                }
            })
            .collect::<String>();
        if filtered_number.len() < 10 || filtered_number.starts_with('0') {
            // invalid number
            filtered_number
        } else {
            let first_country_code_digit = filtered_number[1..2].parse::<u8>().unwrap();
            if first_country_code_digit == 1 || first_country_code_digit == 7 {
                return filtered_number;
            }
            let first_two_country_code_digits = &filtered_number[1..3].parse::<u8>().unwrap();
            match first_two_country_code_digits {
                20 | 27 | 30 | 31 | 32 | 33 | 34 | 36 | 40 | 41 | 43 | 44 | 45 | 46 | 47 | 48
                | 49 | 51 | 52 | 53 | 54 | 55 | 56 | 57 | 58 | 60 | 61 | 62 | 63 | 64 | 65 | 66
                | 70 | 71 | 72 | 73 | 74 | 75 | 76 | 77 | 78 | 79 | 81 | 82 | 84 | 86 | 90 | 91
                | 92 | 93 | 94 | 95 | 98 => {
                    if &filtered_number[3..4] == "0" {
                        format!("{}{}", &filtered_number[0..3], &filtered_number[4..])
                    } else {
                        filtered_number
                    }
                }
                21 | 22 | 23 | 24 | 25 | 26 | 29 | 35 | 37 | 38 | 42 | 50 | 59 | 67 | 68 | 69
                | 80 | 85 | 87 | 88 | 96 | 97 | 99 => {
                    if &filtered_number[4..5] == "0" {
                        format!("{}{}", &filtered_number[0..4], &filtered_number[5..])
                    } else {
                        filtered_number
                    }
                }
                39 => filtered_number,
                _ => filtered_number,
            }
        }
    }
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

pub fn normalize_city(city_name: &str) -> String {
    let mut normalized = city_name
        .nfkd()
        .flat_map(|it| match get_general_category(it) {
            GeneralCategory::UppercaseLetter | GeneralCategory::LowercaseLetter => Some(it),
            GeneralCategory::OtherPunctuation if it == '\'' => Some('\''),
            GeneralCategory::FinalPunctuation if it == '’' => Some('\''),
            GeneralCategory::SpaceSeparator => Some(' '),
            GeneralCategory::DashPunctuation => Some(' '),
            _ => None,
        })
        .collect::<String>()
        .trim()
        .to_lowercase();
    let len = normalized.len();
    let mut start = 0usize;
    while let Some(mut pos) = normalized[start..].find("saint") {
        pos += start;
        start = pos + 2;
        if pos > 0 && &normalized[pos - 1..pos] != " " {
            continue;
        }
        let remaining = len - pos - 5;
        if remaining == 0 {
            normalized.replace_range(pos.., "st");
        } else if remaining == 1 {
            match &normalized[len - 1..] {
                "e" | " " => normalized.replace_range(pos..pos + 5, "st"),
                _ => {}
            }
        } else {
            match &normalized[pos + 5..pos + 6] {
                " " => normalized.replace_range(pos..pos + 5, "st"),
                "e" => {
                    if &normalized[pos + 6..pos + 7] == " " {
                        normalized.replace_range(pos..pos + 5, "st")
                    }
                }
                _ => {}
            }
        }
    }
    normalized
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

    #[test]
    fn test_normalize_phone_number() {
        assert_eq!(
            "+1234567890",
            normalize_phone_number("+1 (234) 567-890", 33)
        );
        assert_eq!("+33601234567", normalize_phone_number("06 01 23 45 67", 33));
        assert_eq!("+33601234567", normalize_phone_number("+330601234567", 33));
        assert_eq!(
            "+33601234567",
            normalize_phone_number("+33 (0)6 01 23 45 67", 33)
        );
        assert_eq!(
            "+33601234567",
            normalize_phone_number("+33 6 01 23 45 67", 33)
        );
        assert_eq!(
            "+35541234567",
            normalize_phone_number("+355 041234567", 355)
        );
        assert_eq!(
            "+390612345678",
            normalize_phone_number("+39 06 12345678", 39)
        );
    }

    #[test]
    fn test_normalize_city() {
        assert_eq!("st denis", normalize_city("Saint-Denis"));
        assert_eq!("grand st denis", normalize_city("Grand Saint-Denis"));
        assert_eq!("le mont st michel", normalize_city("Le Mont Saint Michel"));
        assert_eq!("ste marie", normalize_city("Sainte-Marie"));
        assert_eq!("terre ste", normalize_city("Terre-Sainte"));
        assert_eq!("tousaint", normalize_city("Tousaint"));
    }
}
