// This file contains hand-written prost types for the TPU RuntimeMetricService.
//
// Proto source: cloud/tpu/lib/monitoring/runtime/proto/tpu_metric_service.proto
// Package: tpu.monitoring.runtime
//
// Captured from a live TPU runtime via gRPC reflection (systing --dump-tpu-proto).
// Only the types needed for metric polling are included.

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MetricRequest {
    #[prost(string, optional, tag = "1")]
    pub metric_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag = "2")]
    pub skip_node_aggregation: ::core::option::Option<bool>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MetricResponse {
    #[prost(message, optional, tag = "1")]
    pub metric: ::core::option::Option<TpuMetric>,
    #[prost(message, optional, tag = "2")]
    pub streamz_metric: ::core::option::Option<StreamzMetric>,
    #[prost(enumeration = "MetricType", optional, tag = "3")]
    pub metric_type: ::core::option::Option<i32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum MetricType {
    Unknown = 0,
    Libtpu = 1,
    Streamz = 2,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TpuMetric {
    #[prost(string, optional, tag = "1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(string, optional, tag = "2")]
    pub description: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag = "3")]
    pub metrics: ::prost::alloc::vec::Vec<Metric>,
}

/// Streamz metric (opaque for now — we focus on TPUMetric/LIBTPU type).
/// Streamz metric — wraps streamz.ReadResponse for Streamz-type metrics.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamzMetric {
    #[prost(string, optional, tag = "1")]
    pub name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag = "2")]
    pub read_response: ::prost::alloc::vec::Vec<StreamzReadResponse>,
}

/// Subset of streamz.ReadResponse — contains point sets with metric values.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamzReadResponse {
    // field #1 is Entity (labels) — skipped for now
    #[prost(message, repeated, tag = "2")]
    pub point_set: ::prost::alloc::vec::Vec<StreamzPointSet>,
}

/// Subset of streamz.PointSet — a named set of data points.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamzPointSet {
    #[prost(string, optional, tag = "1")]
    pub metric_name: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, repeated, tag = "2")]
    pub point: ::prost::alloc::vec::Vec<StreamzPoint>,
}

/// Subset of streamz.Point — a single data point with typed value.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamzPoint {
    // field #1 is repeated Column (labels) — skipped
    #[prost(bool, optional, tag = "2")]
    pub bool_value: ::core::option::Option<bool>,
    #[prost(string, optional, tag = "3")]
    pub string_value: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(int64, optional, tag = "4")]
    pub int64_value: ::core::option::Option<i64>,
    #[prost(double, optional, tag = "5")]
    pub double_value: ::core::option::Option<f64>,
    #[prost(message, optional, tag = "6")]
    pub distribution_value: ::core::option::Option<StreamzDistribution>,
    // field #7, #8 are timestamps — skipped
}

/// Subset of streamz.Distribution — distribution statistics.
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StreamzDistribution {
    #[prost(int64, optional, tag = "1")]
    pub count: ::core::option::Option<i64>,
    #[prost(double, optional, tag = "2")]
    pub mean: ::core::option::Option<f64>,
    #[prost(double, optional, tag = "3")]
    pub sum_of_squared_deviation: ::core::option::Option<f64>,
    #[prost(double, optional, tag = "4")]
    pub minimum: ::core::option::Option<f64>,
    #[prost(double, optional, tag = "5")]
    pub maximum: ::core::option::Option<f64>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Metric {
    #[prost(message, optional, tag = "1")]
    pub attribute: ::core::option::Option<Attribute>,
    #[prost(message, optional, tag = "3")]
    pub gauge: ::core::option::Option<Gauge>,
    #[prost(message, optional, tag = "4")]
    pub counter: ::core::option::Option<Counter>,
    #[prost(message, optional, tag = "5")]
    pub distribution: ::core::option::Option<Distribution>,
    #[prost(message, optional, tag = "6")]
    pub summary: ::core::option::Option<Summary>,
    // Timestamp fields (tags 2, 7) omitted — not needed for value extraction
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Attribute {
    #[prost(string, optional, tag = "1")]
    pub key: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(message, optional, tag = "2")]
    pub value: ::core::option::Option<AttrValue>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct AttrValue {
    #[prost(string, optional, tag = "1")]
    pub string_attr: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag = "2")]
    pub bool_attr: ::core::option::Option<bool>,
    #[prost(int64, optional, tag = "3")]
    pub int_attr: ::core::option::Option<i64>,
    #[prost(double, optional, tag = "4")]
    pub double_attr: ::core::option::Option<f64>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Gauge {
    #[prost(double, optional, tag = "1")]
    pub as_double: ::core::option::Option<f64>,
    #[prost(int64, optional, tag = "2")]
    pub as_int: ::core::option::Option<i64>,
    #[prost(string, optional, tag = "3")]
    pub as_string: ::core::option::Option<::prost::alloc::string::String>,
    #[prost(bool, optional, tag = "4")]
    pub as_bool: ::core::option::Option<bool>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Counter {
    #[prost(double, optional, tag = "1")]
    pub as_double: ::core::option::Option<f64>,
    #[prost(uint64, optional, tag = "2")]
    pub as_int: ::core::option::Option<u64>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Distribution {
    #[prost(int64, optional, tag = "1")]
    pub count: ::core::option::Option<i64>,
    #[prost(double, optional, tag = "2")]
    pub mean: ::core::option::Option<f64>,
    #[prost(double, optional, tag = "3")]
    pub min: ::core::option::Option<f64>,
    #[prost(double, optional, tag = "4")]
    pub max: ::core::option::Option<f64>,
    #[prost(double, optional, tag = "5")]
    pub sum_of_squared_deviation: ::core::option::Option<f64>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Summary {
    #[prost(uint64, optional, tag = "1")]
    pub sample_count: ::core::option::Option<u64>,
    #[prost(double, optional, tag = "2")]
    pub sample_sum: ::core::option::Option<f64>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SupportedMetric {
    #[prost(string, optional, tag = "1")]
    pub metric_name: ::core::option::Option<::prost::alloc::string::String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListSupportedMetricsRequest {
    #[prost(string, optional, tag = "1")]
    pub filter: ::core::option::Option<::prost::alloc::string::String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListSupportedMetricsResponse {
    #[prost(message, repeated, tag = "1")]
    pub supported_metric: ::prost::alloc::vec::Vec<SupportedMetric>,
}

/// Generated gRPC client for RuntimeMetricService.
pub mod runtime_metric_service_client {
    #![allow(
        unused_variables,
        dead_code,
        missing_docs,
        clippy::wildcard_imports,
        clippy::let_unit_value,
    )]
    use tonic::codegen::*;
    use tonic::codegen::http::Uri;

    #[derive(Debug, Clone)]
    pub struct RuntimeMetricServiceClient<T> {
        inner: tonic::client::Grpc<T>,
    }

    impl RuntimeMetricServiceClient<tonic::transport::Channel> {
        pub async fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
        where
            D: TryInto<tonic::transport::Endpoint>,
            D::Error: Into<StdError>,
        {
            let conn = tonic::transport::Endpoint::new(dst)?.connect().await?;
            Ok(Self::new(conn))
        }
    }

    impl<T> RuntimeMetricServiceClient<T>
    where
        T: tonic::client::GrpcService<tonic::body::Body>,
        T::Error: Into<StdError>,
        T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
        <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
    {
        pub fn new(inner: T) -> Self {
            let inner = tonic::client::Grpc::new(inner);
            Self { inner }
        }

        pub fn with_origin(inner: T, origin: Uri) -> Self {
            let inner = tonic::client::Grpc::with_origin(inner, origin);
            Self { inner }
        }

        /// Limits the maximum size of a decoded message.
        #[must_use]
        pub fn max_decoding_message_size(mut self, limit: usize) -> Self {
            self.inner = self.inner.max_decoding_message_size(limit);
            self
        }

        /// Get a runtime metric by name.
        pub async fn get_runtime_metric(
            &mut self,
            request: impl tonic::IntoRequest<super::MetricRequest>,
        ) -> std::result::Result<tonic::Response<super::MetricResponse>, tonic::Status> {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("Service was not ready: {}", e.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/tpu.monitoring.runtime.RuntimeMetricService/GetRuntimeMetric",
            );
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "tpu.monitoring.runtime.RuntimeMetricService",
                "GetRuntimeMetric",
            ));
            self.inner.unary(req, path, codec).await
        }

        /// List supported metrics.
        pub async fn list_supported_metrics(
            &mut self,
            request: impl tonic::IntoRequest<super::ListSupportedMetricsRequest>,
        ) -> std::result::Result<
            tonic::Response<super::ListSupportedMetricsResponse>,
            tonic::Status,
        > {
            self.inner.ready().await.map_err(|e| {
                tonic::Status::unknown(format!("Service was not ready: {}", e.into()))
            })?;
            let codec = tonic_prost::ProstCodec::default();
            let path = http::uri::PathAndQuery::from_static(
                "/tpu.monitoring.runtime.RuntimeMetricService/ListSupportedMetrics",
            );
            let mut req = request.into_request();
            req.extensions_mut().insert(GrpcMethod::new(
                "tpu.monitoring.runtime.RuntimeMetricService",
                "ListSupportedMetrics",
            ));
            self.inner.unary(req, path, codec).await
        }
    }
}
