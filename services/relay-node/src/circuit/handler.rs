use crate::circuit::entry::EntryCircuitHandler;
use crate::circuit::exit::ExitCircuitHandler;
use crate::circuit::middle::MiddleCircuitHandler;
use crate::metrics::RelayMetrics;
use common::{
    RelayReadHalf, RelayStream, RelayWriteHalf,
    crypto::{CipherPair, SessionKey},
    protocol::{CircuitId, Message, MessageCommand},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum CircuitState {
    Initializing,
    Active,
    Closing,
    Closed,
}

/// Enum-based circuit handler dispatch (no trait objects, no async_trait).
pub enum CircuitHandler {
    Entry(EntryCircuitHandler),
    Middle(MiddleCircuitHandler),
    Exit(ExitCircuitHandler),
}

impl CircuitHandler {
    pub async fn handle_message(
        &mut self,
        msg: Message,
        prev_hop_write: Option<Arc<Mutex<RelayWriteHalf>>>,
    ) -> anyhow::Result<Option<Message>> {
        match self {
            CircuitHandler::Entry(handler) => handler.handle_message(msg).await,
            CircuitHandler::Middle(handler) => handler.handle_message(msg).await,
            CircuitHandler::Exit(handler) => handler.handle_message(msg, prev_hop_write).await,
        }
    }

    #[allow(dead_code)]
    pub fn circuit_id(&self) -> CircuitId {
        match self {
            CircuitHandler::Entry(handler) => handler.circuit_id(),
            CircuitHandler::Middle(handler) => handler.circuit_id(),
            CircuitHandler::Exit(handler) => handler.circuit_id(),
        }
    }

    #[allow(dead_code)]
    pub fn state(&self) -> CircuitState {
        match self {
            CircuitHandler::Entry(handler) => handler.state(),
            CircuitHandler::Middle(handler) => handler.state(),
            CircuitHandler::Exit(handler) => handler.state(),
        }
    }

    #[allow(dead_code)]
    pub fn session_key(&self) -> Option<&SessionKey> {
        match self {
            CircuitHandler::Entry(handler) => handler.session_key(),
            CircuitHandler::Middle(handler) => handler.session_key(),
            CircuitHandler::Exit(handler) => handler.session_key(),
        }
    }

    #[allow(dead_code)]
    pub fn close(&mut self) {
        match self {
            CircuitHandler::Entry(handler) => handler.close(),
            CircuitHandler::Middle(handler) => handler.close(),
            CircuitHandler::Exit(handler) => handler.close(),
        }
    }

    pub async fn handle_backward_relay(&mut self, msg: Message) -> anyhow::Result<Option<Message>> {
        match self {
            CircuitHandler::Entry(handler) => handler.handle_backward_relay(msg).await,
            CircuitHandler::Middle(handler) => handler.handle_backward_relay(msg).await,
            CircuitHandler::Exit(_) => Ok(Some(msg)),
        }
    }

    pub fn spawn_nexthop_reader(
        &mut self,
        circuit_registry: Arc<Mutex<CircuitRegistry>>,
        client_write: Arc<Mutex<RelayWriteHalf>>,
        metrics: Arc<RelayMetrics>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        match self {
            CircuitHandler::Entry(handler) => {
                handler.spawn_nexthop_reader(circuit_registry, client_write, metrics)
            }
            CircuitHandler::Middle(handler) => {
                handler.spawn_nexthop_reader(circuit_registry, client_write, metrics)
            }
            CircuitHandler::Exit(_) => None,
        }
    }
}

/// Registry of all circuits handled by this relay node.
pub struct CircuitRegistry {
    circuits: HashMap<CircuitId, CircuitHandler>,
    #[allow(dead_code)]
    next_circuit_id: CircuitId,
}

impl CircuitRegistry {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
            next_circuit_id: 1,
        }
    }

    #[allow(dead_code)]
    pub fn allocate_circuit_id(&mut self) -> CircuitId {
        let id = self.next_circuit_id;
        self.next_circuit_id = self.next_circuit_id.wrapping_add(1);
        id
    }

    pub fn add_circuit(&mut self, circuit_id: CircuitId, handler: CircuitHandler) {
        self.circuits.insert(circuit_id, handler);
    }

    pub fn get_circuit_mut(&mut self, circuit_id: CircuitId) -> Option<&mut CircuitHandler> {
        self.circuits.get_mut(&circuit_id)
    }

    #[allow(dead_code)]
    pub fn remove_circuit(&mut self, circuit_id: CircuitId) -> Option<CircuitHandler> {
        self.circuits.remove(&circuit_id)
    }

    #[allow(dead_code)]
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    pub fn circuit_summaries(&self) -> Vec<(CircuitId, CircuitState)> {
        self.circuits
            .iter()
            .map(|(id, handler)| (*id, handler.state()))
            .collect()
    }

    pub async fn handle_message(
        &mut self,
        msg: Message,
        prev_hop_write: Option<Arc<Mutex<RelayWriteHalf>>>,
    ) -> anyhow::Result<Option<Message>> {
        let circuit_id = msg.circuit_id;

        if let Some(handler) = self.get_circuit_mut(circuit_id) {
            handler.handle_message(msg, prev_hop_write).await
        } else if msg.command == MessageCommand::Create {
            Ok(None)
        } else {
            Err(anyhow::anyhow!("Circuit {} not found", circuit_id))
        }
    }

    pub async fn handle_backward_message(
        &mut self,
        msg: Message,
    ) -> anyhow::Result<Option<Message>> {
        let circuit_id = msg.circuit_id;

        if let Some(handler) = self.get_circuit_mut(circuit_id) {
            handler.handle_backward_relay(msg).await
        } else {
            Err(anyhow::anyhow!(
                "Circuit {} not found for backward message",
                circuit_id
            ))
        }
    }
}

impl Default for CircuitRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Base circuit context shared by all handler types.
#[derive(Debug)]
pub struct CircuitContext {
    pub circuit_id: CircuitId,
    pub state: CircuitState,
    pub session_key: Option<SessionKey>,
    pub cipher_pair: Option<CipherPair>,
}

impl CircuitContext {
    pub fn new(circuit_id: CircuitId) -> Self {
        Self {
            circuit_id,
            state: CircuitState::Initializing,
            session_key: None,
            cipher_pair: None,
        }
    }

    /// Mark circuit as active with session key and create stateful cipher pair.
    pub fn activate(&mut self, session_key: SessionKey) {
        self.cipher_pair = Some(CipherPair::new(&session_key));
        self.session_key = Some(session_key);
        self.state = CircuitState::Active;
    }

    pub fn close(&mut self) {
        self.state = CircuitState::Closed;
        self.session_key = None;
        self.cipher_pair = None;
    }
}

pub struct NextHop {
    pub write: RelayWriteHalf,
    pub read: Option<RelayReadHalf>,
}

impl NextHop {
    pub fn new(stream: RelayStream) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            write,
            read: Some(read),
        }
    }

    pub fn take_read(&mut self) -> Option<RelayReadHalf> {
        self.read.take()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use common::crypto::SessionKey;

    #[test]
    fn test_circuit_context_new() {
        let ctx = CircuitContext::new(42);
        assert_eq!(ctx.circuit_id, 42);
        assert_eq!(ctx.state, CircuitState::Initializing);
        assert!(ctx.session_key.is_none());
        assert!(ctx.cipher_pair.is_none());
    }

    #[test]
    fn test_circuit_context_activate() {
        let mut ctx = CircuitContext::new(1);
        let key = SessionKey::new([1u8; 16], [2u8; 16]);
        ctx.activate(key.clone());

        assert_eq!(ctx.state, CircuitState::Active);
        assert_eq!(ctx.session_key.unwrap(), key);
        assert!(ctx.cipher_pair.is_some());
    }

    #[test]
    fn test_circuit_context_close() {
        let mut ctx = CircuitContext::new(1);
        ctx.activate(SessionKey::new([1u8; 16], [2u8; 16]));
        ctx.close();

        assert_eq!(ctx.state, CircuitState::Closed);
        assert!(ctx.session_key.is_none());
        assert!(ctx.cipher_pair.is_none());
    }

    #[test]
    fn test_circuit_registry_new_empty() {
        let reg = CircuitRegistry::new();
        assert_eq!(reg.circuit_count(), 0);
    }

    #[test]
    fn test_circuit_registry_allocate_id() {
        let mut reg = CircuitRegistry::new();
        assert_eq!(reg.allocate_circuit_id(), 1);
        assert_eq!(reg.allocate_circuit_id(), 2);
        assert_eq!(reg.allocate_circuit_id(), 3);
    }

    #[test]
    fn test_circuit_registry_default() {
        let reg = CircuitRegistry::default();
        assert_eq!(reg.circuit_count(), 0);
    }
}
