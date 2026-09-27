//! Shared fixture admission: retain one prepared package while real peers ACK.
use gcoms_node::NodeHandle;
use std::time::Duration;

#[allow(dead_code)] // This shared module is also used by the larger overlay fixture.
pub async fn welcome(
    owner: &NodeHandle,
    channel: &str,
    package: &[u8],
    name: &str,
) -> Result<Vec<u8>, String> {
    welcome_with_timeout(owner, channel, package, name, Duration::from_secs(30)).await
}

pub async fn welcome_with_timeout(
    owner: &NodeHandle,
    channel: &str,
    package: &[u8],
    name: &str,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    tokio::time::timeout(timeout, async {
        loop {
            match owner.admit_channel(channel, package, name).await {
                Err(error)
                    if error == "channel messages still awaiting acknowledgements"
                        || error == "membership change still awaiting acknowledgements" =>
                {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                result => return result,
            }
        }
    })
    .await
    .map_err(|_| {
        format!(
            "fixture admission did not settle within {}s",
            timeout.as_secs()
        )
    })?
}
