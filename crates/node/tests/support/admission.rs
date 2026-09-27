//! Shared fixture admission: retain one prepared package while real peers ACK.
use gcoms_node::NodeHandle;
use std::time::Duration;

pub async fn welcome(
    owner: &NodeHandle,
    channel: &str,
    package: &[u8],
    name: &str,
) -> Result<Vec<u8>, String> {
    tokio::time::timeout(Duration::from_secs(30), async {
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
    .map_err(|_| "fixture admission did not settle within 30s".to_string())?
}
