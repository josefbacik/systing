/// Generated ProfilerService gRPC client and request/response types (tensorflow package).
/// The `profiler` submodule contains XSpace/XPlane types (tensorflow.profiler package).
pub mod profiler_service {
    /// The tensorflow.profiler types (XSpace, XPlane, XLine, XEvent, etc.).
    pub mod profiler {
        include!("tensorflow.profiler.rs");
    }

    include!("tensorflow.rs");

    /// Re-export the gRPC client module.
    pub use profiler_service_client::ProfilerServiceClient;
}

/// Re-export XSpace/XPlane types at a convenient path.
pub mod xplane {
    pub use super::profiler_service::profiler::*;
}
