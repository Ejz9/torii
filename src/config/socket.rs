use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};
use tracing::error;

use crate::state::AppState;

pub async fn start_config_listener(state: Arc<AppState>) {
    std::fs::remove_file("/tmp/torii.sock").ok();
    let Ok(listener) = UnixListener::bind("/tmp/torii.sock") else {
        error!("FATAL: Failed to create socket, does it already exist?");
        std::process::exit(1)
    };
    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                let mut buffer = vec![0u8; 65536];
                let Ok(bytes) = stream.read(&mut buffer).await else {
                    let _ = stream.write_u8(0).await;
                    continue;
                };
                let Some(config) = postcard::from_bytes(&buffer[..bytes]).ok() else {
                    let _ = stream.write_u8(0).await;
                    continue;
                };
                state.dynamic_config.store(Arc::new(config));
                let _ = stream.write_u8(1).await;
            }
            Err(e) => {
                error!("FATAL: Failed to recieve config bytes: {}", e);
                std::process::exit(1)
            }
        }
    }
}
