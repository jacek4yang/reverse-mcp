//! Broker<->worker IPC protocol: newline-delimited compact JSON over worker
//! stdio. Shared by rmcp-worker (server side) and rmcp-broker (client side).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

/// Request from broker to worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerRequest {
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// Response from worker to broker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerResponse {
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<WorkerErrorBody>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerErrorBody {
    pub code: String,
    pub message: String,
}

impl WorkerResponse {
    pub fn ok(id: u64, result: Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: u64, err: &Error) -> Self {
        Self {
            id,
            result: None,
            error: Some(WorkerErrorBody {
                code: err.code().to_string(),
                message: err.to_string(),
            }),
        }
    }

    pub fn into_result(self) -> Result<Value> {
        match self {
            WorkerResponse {
                result: Some(v), ..
            } => Ok(v),
            WorkerResponse { error: Some(e), .. } => {
                Err(Error::Worker(format!("{}: {}", e.code, e.message)))
            }
            WorkerResponse { .. } => Err(Error::Ipc("empty worker response".into())),
        }
    }
}

/// Hello/identify message sent by the worker on stdout right after start.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerHello {
    pub protocol: u32,
    pub ida_version: String,
    pub pid: u32,
    pub ida_dir: String,
    pub idausr: String,
}

pub const PROTOCOL_VERSION: u32 = 1;

/// Frame reader: newline-delimited JSON over any `BufRead`.
pub struct FrameReader<R: std::io::BufRead> {
    inner: R,
}

impl<R: std::io::BufRead> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner }
    }

    /// Read one JSON value; None on clean EOF.
    pub fn read<T: for<'de> Deserialize<'de>>(&mut self) -> Result<Option<T>> {
        let mut line = String::new();
        let n = self.inner.read_line(&mut line).map_err(Error::Io)?;
        if n == 0 {
            return Ok(None);
        }
        serde_json::from_str(line.trim())
            .map(Some)
            .map_err(|e| Error::Ipc(format!("bad frame: {e}")))
    }
}

/// Write one JSON value as a newline-terminated compact frame.
pub fn write_frame<W: std::io::Write>(mut w: W, value: &impl Serialize) -> Result<()> {
    let mut buf = serde_json::to_vec(value).map_err(|e| Error::Ipc(e.to_string()))?;
    buf.push(b'\n');
    w.write_all(&buf).map_err(Error::Io)?;
    w.flush().map_err(Error::Io)
}

/// Async frame reader for tokio-backed IO (broker side).
#[cfg(feature = "tokio-async")]
pub mod r#async {
    use super::*;
    use tokio::io::{AsyncBufRead, AsyncBufReadExt};

    pub struct AsyncFrameReader<R: AsyncBufRead + Unpin> {
        inner: R,
    }

    impl<R: AsyncBufRead + Unpin> AsyncFrameReader<R> {
        pub fn new(inner: R) -> Self {
            Self { inner }
        }

        pub async fn read<T: for<'de> Deserialize<'de>>(&mut self) -> Result<Option<T>> {
            let mut line = String::new();
            let n = self.inner.read_line(&mut line).await?;
            if n == 0 {
                return Ok(None);
            }
            serde_json::from_str(line.trim())
                .map(Some)
                .map_err(|e| Error::Ipc(format!("bad frame: {e}")))
        }

        pub fn into_inner(self) -> R {
            self.inner
        }
    }

    /// Write one JSON value as a newline-terminated compact frame (async).
    pub async fn write_frame_async<W>(mut w: W, value: &impl Serialize) -> Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut buf = serde_json::to_vec(value).map_err(|e| Error::Ipc(e.to_string()))?;
        buf.push(b'\n');
        tokio::io::AsyncWriteExt::write_all(&mut w, &buf).await?;
        tokio::io::AsyncWriteExt::flush(&mut w).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;

    #[test]
    fn roundtrip_frames() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(
            &mut buf,
            &WorkerRequest {
                id: 7,
                method: "functions".into(),
                params: serde_json::json!({"offset": 0}),
            },
        )
        .unwrap();
        buf.extend_from_slice(b"{\"id\":8,\"method\":\"close\"}\n");

        let mut reader = FrameReader::new(BufReader::new(&buf[..]));
        let r1: WorkerRequest = reader.read().unwrap().unwrap();
        assert_eq!(r1.id, 7);
        assert_eq!(r1.method, "functions");
        let r2: WorkerRequest = reader.read().unwrap().unwrap();
        assert_eq!(r2.id, 8);
        assert!(reader.read::<WorkerRequest>().unwrap().is_none());
    }

    #[test]
    fn response_into_result() {
        let ok = WorkerResponse::ok(1, serde_json::json!({"x": 1}));
        assert_eq!(ok.into_result().unwrap()["x"], 1);
        let err = WorkerResponse::err(2, &Error::UnknownDb("db9".into()));
        let e = err.into_result().unwrap_err();
        assert!(e.to_string().contains("unknown_db"));
    }
}
