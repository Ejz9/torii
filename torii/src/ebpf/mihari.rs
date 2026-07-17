use std::sync::Arc;

use crate::{ebpf::kekkai_manager::MihariEntry, state::AppState};

pub async fn run(
    state: Arc<AppState>,
    tx: tokio::sync::mpsc::Sender<MihariEntry>,
) {
    
}

