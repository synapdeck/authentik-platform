use crate::{
    App,
    auth::{aws, gcp, k8s, raw},
};
use clap::Subcommand;
use eyre::Result;

#[derive(Subcommand, Clone)]
pub enum AuthCommands {
    /// Authenticate to arbitrary API calls.
    Raw {
        #[arg(short, long, required = true)]
        client_id: String,
    },
    /// Authenticate to AWS with the authentik profile.
    Aws {
        #[arg(short, long, required = true)]
        client_id: String,
        #[arg(short, long, required = true)]
        role_arn: String,
        #[arg(short = 'e', long, required = true)]
        region: String,
    },
    /// Authenticate to Google Cloud with the authentik profile.
    ///
    /// Intended as the command of an executable-sourced credential config, as
    /// created by `gcloud iam workforce-pools create-cred-config
    /// --executable-command`.
    Gcp {
        #[arg(short, long, required = true)]
        client_id: String,
    },
    /// Authenticate to a Kubernetes Cluster with the authentik profile.
    Kubectl {
        #[arg(short, long, required = true)]
        client_id: String,
    },
}

pub async fn raw(mut app: App, client_id: &str) -> Result<()> {
    let creds = raw::get_credentials(
        app.clone().user().await?,
        raw::CredentialsOpts {
            profile: app.profile().await,
            client_id: client_id.to_owned(),
        },
    )
    .await?;
    println!("{}", creds.access_token);
    Ok(())
}

pub async fn aws(mut app: App, client_id: &str, role_arn: &str, region: &str) -> Result<()> {
    let creds = aws::get_credentials(
        app.clone().user().await?,
        aws::CredentialsOpts {
            profile: app.profile().await,
            client_id: client_id.to_owned(),
            role_arn: role_arn.to_owned(),
            region: region.to_owned(),
        },
    )
    .await?;
    print!("{}", serde_json::to_string(&creds)?);
    Ok(())
}

pub async fn kubectl(mut app: App, client_id: &str) -> Result<()> {
    let creds = k8s::get_credentials(
        app.clone().user().await?,
        k8s::CredentialsOpts {
            profile: app.profile().await,
            client_id: client_id.to_owned(),
        },
    )
    .await?;
    print!("{}", serde_json::to_string(&creds)?);
    Ok(())
}

pub async fn gcp(mut app: App, client_id: &str) -> Result<()> {
    // Google's libraries pass the configured subject token type in the
    // environment and require the response to echo it back.
    let token_type = match std::env::var("GOOGLE_EXTERNAL_ACCOUNT_TOKEN_TYPE") {
        Ok(t) if t == gcp::TOKEN_TYPE_ID_TOKEN => t,
        _ => gcp::TOKEN_TYPE_JWT.to_owned(),
    };
    let res = async {
        gcp::get_credentials(
            app.clone().user().await?,
            gcp::CredentialsOpts {
                profile: app.profile().await,
                client_id: client_id.to_owned(),
                token_type,
            },
        )
        .await
    }
    .await;
    let out = match &res {
        Ok(creds) => creds.clone(),
        Err(e) => gcp::ExecutableResponse::error("AUTHENTIK_ERROR", format!("{e:#}")),
    };
    let body = serde_json::to_string(&out)?;
    // When the credential config sets output_file, the executable is expected to
    // write its response there for Google's libraries to reuse.
    if let Ok(path) = std::env::var("GOOGLE_EXTERNAL_ACCOUNT_OUTPUT_FILE")
        && out.success
    {
        std::fs::write(&path, &body)?;
    }
    print!("{body}");
    res.map(|_| ())
}
