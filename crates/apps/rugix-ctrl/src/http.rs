//! TLS initialization for HTTP downloads.

/// Install the process-wide TLS configuration.
pub fn setup() {
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        // This should never happen as there is no pre-installed provider at this
        // point, so the installation should always succeed.
        eprintln!("unable to install default crypto provider, continuing anyway");
    }
}

#[cfg(test)]
mod tests {
    /// Verify that the update downloader accepts HTTPS using the system trust store.
    #[test]
    fn https_request_does_not_panic() {
        super::setup();
        crate::http_source::HttpSource::new(
            "https://rugix.org",
            crate::http_source::RangeQueryStrategy::Disabled,
            crate::http_source::RetryConfig::default(),
            &crate::http_source::HttpFetchConfig::default(),
        )
        .unwrap();
    }
}
