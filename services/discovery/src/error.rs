use tonic::Status;

/// Registry-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Insufficient nodes: {0}")]
    InsufficientNodes(String),

    #[error("Node already registered: {0}")]
    #[allow(dead_code)]
    NodeAlreadyExists(String),

    #[error("Invalid node data: {0}")]
    #[allow(dead_code)]
    InvalidNode(String),
}

impl From<RegistryError> for Status {
    fn from(err: RegistryError) -> Self {
        match err {
            RegistryError::NodeNotFound(msg) => Status::not_found(msg),
            RegistryError::InsufficientNodes(msg) => Status::unavailable(msg),
            RegistryError::NodeAlreadyExists(msg) => Status::already_exists(msg),
            RegistryError::InvalidNode(msg) => Status::invalid_argument(msg),
        }
    }
}
