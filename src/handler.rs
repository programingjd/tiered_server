use crate::download::download;
use crate::env::ConfigurationKey::{StaticGithubBranch, StaticGithubRepository, StaticGithubUser};
use crate::env::secret_value;
use crate::headers::HSelector;
use pinboard::Pinboard;
use std::sync::{Arc, LazyLock};
use zip_static_handler::github::zip_download_branch_url;
use zip_static_handler::handler::Handler;

static HANDLER: LazyLock<Pinboard<Arc<Handler>>> = LazyLock::new(Pinboard::new_empty);

pub async fn static_handler() -> Arc<Handler> {
    if let Some(handler) = HANDLER.get_ref() {
        handler.clone()
    } else {
        let github_user = secret_value(StaticGithubUser)
            .expect("missing github user for static content repository");
        let github_repository = secret_value(StaticGithubRepository)
            .expect("missing github repository name for static content repository");
        let github_branch = secret_value(StaticGithubBranch)
            .expect("missing github repository branch for static content repository");
        let zip = download(&zip_download_branch_url(
            github_user,
            github_repository,
            github_branch,
        ))
        .await
        .expect("failed to download static content");
        let static_handler = Arc::new(
            Handler::builder()
                .with_custom_header_selector(&HSelector)
                .with_zip_prefix(format!("{github_repository}-{github_branch}/"))
                .with_zip(zip)
                .try_build()
                .expect("failed to extract static content"),
        );
        HANDLER.set(static_handler.clone());
        static_handler
    }
}

pub(crate) fn set(handler: Handler) {
    HANDLER.set(Arc::new(handler));
}
