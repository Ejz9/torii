use keidai::ConnectionEvent;
use tokio_util::sync::CancellationToken;

pub async fn kagura(
    mut event_stream: quinn::SendStream,
    event_rx: flume::Receiver<ConnectionEvent>,
    cancel_token: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            biased;
            _ = cancel_token.cancelled() => break,
            res = event_rx.recv_async() => {
                match res {
                    Ok(event) => {
                        if let Err(e) = event_stream.write_all(event.as_bytes()).await {
                            tracing::warn!("Miko failed to stream event to Torii: {e}");
                            break;
                        }
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        }
    }
    todo!()
}
