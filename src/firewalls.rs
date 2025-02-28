use firewall::builder::{Firewall, IpCidr};
use firewall::cloudflare::fetch_cloudflare_ip_ranges;
use firewall::github::fetch_github_webhook_ip_ranges;
use pinboard::NonEmptyPinboard;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::time::interval;

type UpdatingFirewall = Arc<NonEmptyPinboard<Firewall>>;

pub(crate) fn update_firewall_loop(
    firewall: UpdatingFirewall,
    webhook_firewall: UpdatingFirewall,
    domains: Vec<String>,
    firewall_domains: Vec<String>,
    cloudflare_ip_ranges: Vec<IpCidr>,
    github_ip_ranges: Vec<IpCidr>,
) {
    // Firewall periodic update
    thread::spawn(move || {
        let mut cloudflare_ip_ranges = BTreeSet::from_iter(cloudflare_ip_ranges);
        let mut github_ip_ranges = BTreeSet::from_iter(github_ip_ranges);
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap()
            .block_on(async {
                let mut delay = interval(Duration::from_secs(80_000));
                delay.tick().await;
                loop {
                    delay.tick().await;
                    if let Ok(cidr_list) = fetch_cloudflare_ip_ranges().await {
                        if cidr_list.len() != cloudflare_ip_ranges.len()
                            || cidr_list.iter().any(|it| !cloudflare_ip_ranges.contains(it))
                        {
                            let replacement = Firewall::default()
                                .require_sni()
                                .allow_server_names(domains.iter().cloned())
                                .allow_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
                                .allow_ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
                                .allow_ip_ranges(cidr_list.iter().cloned());
                            cloudflare_ip_ranges = BTreeSet::from_iter(cidr_list);
                            firewall.set(replacement);
                        }
                    }
                    if let Ok(cidr_list) = fetch_github_webhook_ip_ranges().await {
                        if cidr_list.len() != github_ip_ranges.len()
                            || cidr_list.iter().any(|it| !github_ip_ranges.contains(it))
                        {
                            let replacement = Firewall::default()
                                .require_sni()
                                .allow_server_names(firewall_domains.iter().cloned())
                                .allow_ip_ranges(cidr_list.iter().cloned())
                                .allow_ip_ranges(cloudflare_ip_ranges.iter().cloned());
                            github_ip_ranges = BTreeSet::from_iter(cidr_list);
                            webhook_firewall.set(replacement);
                        }
                    }
                }
            })
    });
}
