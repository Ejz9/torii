use crate::ShinshiConfig;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Serialize, Deserialize)]
pub enum ControlMessage {
    Auth { token: Vec<u8> },
    SyncConfig(ShinshiConfig),
    CertRequest { domain: String, csr: Vec<u8> },
    CertResponse { domain: String, cert_chain: String },
    CertError { domain: String, error: String },
    Ready,
}

pub async fn send_control(
    stream: &mut quinn::SendStream,
    msg: &ControlMessage,
) -> anyhow::Result<()> {
    let bytes = postcard::to_allocvec(msg)?;
    stream.write_u16(bytes.len() as u16).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

pub async fn recv_control(stream: &mut quinn::RecvStream) -> anyhow::Result<ControlMessage> {
    let len = stream.read_u16().await? as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(postcard::from_bytes(&buf)?)
}
