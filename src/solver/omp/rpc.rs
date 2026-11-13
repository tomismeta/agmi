use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tokio::io::{AsyncBufReadExt, BufReader};

pub(super) const PHYSICAL: usize = 1024 * 1024;
pub(super) const LOGICAL: usize = MAX_OUTPUT * 6 + 64 * 1024;
const CHUNK: usize = 256 * 1024;
const TOTAL: usize = LOGICAL * 8;
const FRAMES: usize = 256;

fn unbase64(text: &str) -> Result<Vec<u8>> {
    ensure!(
        !text.is_empty() && text.len() <= CHUNK.div_ceil(3) * 4,
        NativeFailure("native_envelope_invalid")
    );
    let bytes = STANDARD
        .decode(text)
        .map_err(|_| NativeFailure("native_envelope_invalid"))?;
    ensure!(
        bytes.len() <= CHUNK,
        NativeFailure("native_envelope_invalid")
    );
    Ok(bytes)
}

struct Pending {
    id: String,
    count: usize,
    next: usize,
    length: usize,
    bytes: Vec<u8>,
}

pub(super) struct Reader<R> {
    reader: BufReader<R>,
    physical: usize,
    logical: usize,
    total: usize,
    frames: usize,
    v2: bool,
    pending: Option<Pending>,
    chunk_ids: std::collections::HashSet<String>,
}
impl<R: AsyncRead + Unpin> Reader<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            physical: PHYSICAL,
            logical: LOGICAL,
            total: 0,
            frames: 0,
            v2: false,
            pending: None,
            chunk_ids: Default::default(),
        }
    }
    pub(super) fn negotiate(&mut self, ready: &Value) -> Result<()> {
        ensure!(
            ready["type"] == "ready"
                && ready["protocolVersion"] == 1
                && ready["supportedProtocolVersions"]
                    .as_array()
                    .is_some_and(|v| v.contains(&json!(2))),
            NativeFailure("native_envelope_invalid")
        );
        let physical = number(ready, "maxFrameBytes")?;
        let logical = number(ready, "maxReassembledFrameBytes")?;
        ensure!(
            (1024..=PHYSICAL).contains(&physical) && logical >= physical,
            NativeFailure("native_envelope_invalid")
        );
        self.physical = physical;
        self.logical = logical.min(LOGICAL);
        Ok(())
    }
    pub(super) fn enable_v2(&mut self) {
        self.v2 = true;
    }
    async fn line(&mut self) -> Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            let available = self
                .reader
                .fill_buf()
                .await
                .map_err(|_| NativeFailure("native_pipe_failed"))?;
            ensure!(
                !available.is_empty(),
                NativeFailure("native_envelope_invalid")
            );
            let end = available.iter().position(|b| *b == b'\n');
            let take = end.map_or(available.len(), |n| n + 1);
            ensure!(
                line.len() + take <= self.physical && self.total + take <= TOTAL,
                NativeFailure("native_output_limit")
            );
            line.extend_from_slice(&available[..take]);
            self.total += take;
            self.reader.consume(take);
            if end.is_some() {
                line.pop();
                return Ok(line);
            }
        }
    }
    pub(super) async fn next(&mut self) -> Result<Value> {
        loop {
            self.frames += 1;
            ensure!(self.frames <= FRAMES, NativeFailure("native_output_limit"));
            let line = self.line().await?;
            let value: Value = serde_json::from_slice(&line)
                .map_err(|_| NativeFailure("native_envelope_invalid"))?;
            ensure!(value.is_object(), NativeFailure("native_envelope_invalid"));
            if value["type"] != "rpc_chunk" {
                ensure!(
                    self.pending.is_none() && line.len() <= self.logical,
                    NativeFailure("native_envelope_invalid")
                );
                return Ok(value);
            }
            ensure!(self.v2, NativeFailure("native_envelope_invalid"));
            let id = value["chunkId"]
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 128)
                .context(NativeFailure("native_envelope_invalid"))?;
            let count = number(&value, "count")?;
            let index = number(&value, "index")?;
            let length = number(&value, "byteLength")?;
            ensure!(
                length >= self.physical
                    && length <= self.logical
                    && count == length.div_ceil(CHUNK)
                    && count >= 2
                    && index < count,
                NativeFailure("native_output_limit")
            );
            let bytes = unbase64(
                value["data"]
                    .as_str()
                    .context(NativeFailure("native_envelope_invalid"))?,
            )?;
            ensure!(
                bytes.len()
                    == if index + 1 == count {
                        length - index * CHUNK
                    } else {
                        CHUNK
                    },
                NativeFailure("native_envelope_invalid")
            );
            if self.pending.is_none() {
                ensure!(
                    index == 0 && self.chunk_ids.insert(id.to_owned()),
                    NativeFailure("native_envelope_invalid")
                );
                self.pending = Some(Pending {
                    id: id.into(),
                    count,
                    next: 0,
                    length,
                    bytes: Vec::with_capacity(length),
                });
            }
            let pending = self.pending.as_mut().expect("pending initialized");
            ensure!(
                pending.id == id
                    && pending.count == count
                    && pending.next == index
                    && pending.length == length,
                NativeFailure("native_run_binding_mismatch")
            );
            pending.bytes.extend_from_slice(&bytes);
            pending.next += 1;
            if pending.next == count {
                let pending = self.pending.take().expect("pending initialized");
                let decoded: Value = serde_json::from_slice(&pending.bytes)
                    .map_err(|_| NativeFailure("native_envelope_invalid"))?;
                ensure!(
                    decoded.is_object() && decoded["type"] != "rpc_chunk",
                    NativeFailure("native_envelope_invalid")
                );
                return Ok(decoded);
            }
        }
    }
}
fn number(value: &Value, key: &str) -> Result<usize> {
    value[key]
        .as_u64()
        .and_then(|v| usize::try_from(v).ok())
        .context(NativeFailure("native_envelope_invalid"))
}

pub(super) async fn send(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    value: &Value,
) -> Result<()> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|_| NativeFailure("native_envelope_invalid"))?;
    ensure!(
        bytes.len() <= (2 * MAX_INPUT + 16 * 1024).div_ceil(3) * 4 + 4096,
        NativeFailure("native_output_limit")
    );
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|_| NativeFailure("native_pipe_failed"))?;
    writer
        .flush()
        .await
        .map_err(|_| NativeFailure("native_pipe_failed"))?;
    Ok(())
}

// This invocation never starts an agent turn. Only these shell notifications are benign.
pub(super) fn notification(value: &Value) -> Result<()> {
    ensure!(
        matches!(
            value["type"].as_str(),
            Some("session_settled" | "session_name_changed" | "available_commands_update")
        ),
        NativeFailure("native_envelope_invalid")
    );
    Ok(())
}

pub(super) async fn response<R: AsyncRead + Unpin>(
    reader: &mut Reader<R>,
    id: &str,
    command: &str,
) -> Result<Value> {
    loop {
        let mut frame = reader.next().await?;
        if frame["type"] == "response" {
            ensure!(
                frame["id"] == id && frame["command"] == command,
                NativeFailure("native_run_binding_mismatch")
            );
            ensure!(
                frame["success"] == true && frame.get("error").is_none(),
                NativeFailure("native_envelope_invalid")
            );
            return Ok(frame.get_mut("data").map_or(Value::Null, Value::take));
        }
        notification(&frame)?;
    }
}

pub(super) async fn exchange<R: AsyncRead + Unpin>(
    writer: &mut (impl tokio::io::AsyncWrite + Unpin),
    reader: &mut Reader<R>,
    request: &Value,
) -> Result<Value> {
    let id = request["id"]
        .as_str()
        .context(NativeFailure("native_envelope_invalid"))?;
    let command = request["type"]
        .as_str()
        .context(NativeFailure("native_envelope_invalid"))?;
    // Native notifications can fill stdout before it reads a large stdin command.
    let (_, data) = tokio::try_join!(send(writer, request), response(reader, id, command))?;
    Ok(data)
}

pub(super) async fn local_completion<R: AsyncRead + Unpin>(
    reader: &mut Reader<R>,
    id: &str,
) -> Result<()> {
    loop {
        let frame = reader.next().await?;
        if frame["type"] == "prompt_result" {
            ensure!(
                frame["id"] == id,
                NativeFailure("native_run_binding_mismatch")
            );
            ensure!(
                frame["agentInvoked"] == false
                    && frame["status"] == "completed"
                    && frame.get("error").is_none(),
                NativeFailure("native_envelope_invalid")
            );
            return Ok(());
        }
        notification(&frame)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_physical_overflow_without_unbounded_read() {
        let bytes = vec![b'x'; PHYSICAL + 1];
        let error = Reader::new(&bytes[..]).next().await.unwrap_err();
        assert_eq!(failure_code(&error), "native_output_limit");
    }
    #[tokio::test]
    async fn rejects_mismatched_response_and_native_error_without_diagnostics() {
        let data = b"{\"type\":\"response\",\"id\":\"wrong\",\"command\":\"get_entries\",\"success\":true}\n";
        let error = response(&mut Reader::new(&data[..]), "expected", "get_entries")
            .await
            .unwrap_err();
        assert_eq!(failure_code(&error), "native_run_binding_mismatch");
        let data = b"{\"type\":\"response\",\"id\":\"expected\",\"command\":\"get_entries\",\"success\":false,\"error\":\"SECRET\"}\n";
        let error = response(&mut Reader::new(&data[..]), "expected", "get_entries")
            .await
            .unwrap_err();
        assert_eq!(failure_code(&error), "native_envelope_invalid");
        assert!(!error.to_string().contains("SECRET"));
    }
    #[tokio::test]
    async fn rejects_agent_turn_and_invalid_utf8() {
        let data = b"{\"type\":\"agent_start\"}\n";
        assert!(
            response(&mut Reader::new(&data[..]), "a", "prompt")
                .await
                .is_err()
        );
        assert!(
            Reader::new(&b"{\"x\":\"\xff\"}\n"[..])
                .next()
                .await
                .is_err()
        );
    }
    #[test]
    fn canonical_base64_and_declared_bounds() {
        assert_eq!(unbase64("//8=").unwrap(), b"\xff\xff");
        assert!(unbase64("//9=").is_err());
        let mut reader = Reader::new(&b""[..]);
        assert!(reader.negotiate(&json!({"type":"ready","protocolVersion":1,"supportedProtocolVersions":[1,2],"maxFrameBytes":PHYSICAL+1,"maxReassembledFrameBytes":LOGICAL})).is_err());
    }
    fn chunked(value: &Value) -> Vec<Value> {
        let bytes = serde_json::to_vec(value).unwrap();
        bytes.chunks(CHUNK).enumerate().map(|(index, data)| json!({
            "type":"rpc_chunk","chunkId":"chunk","index":index,"count":bytes.len().div_ceil(CHUNK),
            "byteLength":bytes.len(),"data":STANDARD.encode(data)
        })).collect()
    }
    fn wire(frames: &[Value]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for frame in frames {
            serde_json::to_writer(&mut bytes, frame).unwrap();
            bytes.push(b'\n');
        }
        bytes
    }
    #[tokio::test]
    async fn consumes_bounded_chunks_and_rejects_reordered_or_replayed_sequences() {
        let expected = json!({"type":"response","output":"a".repeat(PHYSICAL)});
        let frames = chunked(&expected);
        let bytes = wire(&frames);
        let mut reader = Reader::new(&bytes[..]);
        reader.enable_v2();
        assert_eq!(reader.next().await.unwrap(), expected);
        let mut reordered = frames.clone();
        reordered.swap(0, 1);
        let bytes = wire(&reordered);
        let mut reader = Reader::new(&bytes[..]);
        reader.enable_v2();
        assert!(reader.next().await.is_err());
        let bytes = wire(&[frames.clone(), frames].concat());
        let mut reader = Reader::new(&bytes[..]);
        reader.enable_v2();
        reader.next().await.unwrap();
        assert!(reader.next().await.is_err());
    }
    #[tokio::test]
    async fn rejects_oversized_declaration_before_chunk_decode_and_interrupted_chunks() {
        let bytes = wire(&[
            json!({"type":"rpc_chunk","chunkId":"x","index":0,"count":8,"byteLength":LOGICAL+1,"data":"SECRET"}),
        ]);
        let mut reader = Reader::new(&bytes[..]);
        reader.enable_v2();
        let error = reader.next().await.unwrap_err();
        assert_eq!(failure_code(&error), "native_output_limit");
        assert!(!error.to_string().contains("SECRET"));
        let expected = json!({"type":"response","output":"a".repeat(PHYSICAL)});
        let frames = chunked(&expected);
        let bytes = wire(&[
            frames[0].clone(),
            json!({"type":"response","id":"interruption"}),
        ]);
        let mut reader = Reader::new(&bytes[..]);
        reader.enable_v2();
        assert!(reader.next().await.is_err());
    }
    #[tokio::test]
    async fn admission_requires_a_correlated_local_completion() {
        let ack = json!({"type":"response","id":"once","command":"prompt","success":true});
        let completion = json!({"type":"prompt_result","id":"once","agentInvoked":false,"status":"completed","sessionSettled":true});
        let bytes = wire(&[ack.clone(), completion.clone()]);
        let mut reader = Reader::new(&bytes[..]);
        assert!(
            response(&mut reader, "once", "prompt")
                .await
                .unwrap()
                .is_null()
        );
        local_completion(&mut reader, "once").await.unwrap();
        let bytes = wire(&[ack]);
        let mut reader = Reader::new(&bytes[..]);
        response(&mut reader, "once", "prompt").await.unwrap();
        assert!(local_completion(&mut reader, "once").await.is_err());
        let bytes = wire(&[completion]);
        assert_eq!(
            failure_code(
                &local_completion(&mut Reader::new(&bytes[..]), "other")
                    .await
                    .unwrap_err()
            ),
            "native_run_binding_mismatch"
        );
    }
    #[tokio::test]
    async fn native_command_catalog_notification_does_not_reject_readiness() {
        let bytes = b"{\"type\":\"available_commands_update\",\"commands\":[]}\n{\"type\":\"response\",\"id\":\"negotiate\",\"command\":\"negotiate_protocol\",\"success\":true,\"data\":{\"protocolVersion\":2}}\n";
        let result = response(
            &mut Reader::new(&bytes[..]),
            "negotiate",
            "negotiate_protocol",
        )
        .await
        .unwrap();
        assert_eq!(result["protocolVersion"], 2);
    }
    #[tokio::test]
    async fn large_command_drains_native_output_under_pipe_backpressure() {
        let (mut writer, native_input) = tokio::io::duplex(1024);
        let (mut native_output, stdout) = tokio::io::duplex(1024);
        let native = tokio::spawn(async move {
            let notification = json!({"type":"available_commands_update","commands":[],"padding":"n".repeat(8192)});
            native_output
                .write_all(&wire(&[notification]))
                .await
                .unwrap();
            let mut line = String::new();
            BufReader::new(native_input)
                .read_line(&mut line)
                .await
                .unwrap();
            let request: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(request["message"].as_str().unwrap().len(), 32768);
            native_output
                .write_all(&wire(&[
                    json!({"type":"response","id":"once","command":"prompt","success":true}),
                ]))
                .await
                .unwrap();
        });
        let request = json!({"id":"once","type":"prompt","message":"m".repeat(32768)});
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            exchange(&mut writer, &mut Reader::new(stdout), &request),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(result.is_null());
        native.await.unwrap();
    }
}
