//! Keep the loopback proof origin separate from the deny-only proxy listener.

use super::FIXTURE_KEY;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{net::Ipv4Addr, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::timeout,
};

pub const POLICY: &str = "AGMI_OMP_POLICY_CANARY: Return the answer only; use no tools.";
pub const REQUEST_MARKER: &str = "AGMI_OMP_USER_DATA_CANARY";
pub const OUTPUT: &str = r#"{"answer":"agmi-loopback-output"}"#;

#[derive(Clone, Copy, Debug)]
pub(super) enum Case {
    Capture,
    #[cfg(feature = "omp-go-fixture")]
    RejectAuth,
    RejectEffort,
    RejectServedModel,
}

pub(super) struct Probe {
    origin: String,
    proxy: String,
    close: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<()>>,
}

impl Probe {
    pub(super) async fn start(mode: Case, model: &str, effort: &str) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let authority = listener.local_addr()?.to_string();
        let origin = format!("http://{authority}");
        let deny = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy = format!("http://{}", deny.local_addr()?);
        let (close, mut closed) = oneshot::channel();
        let (model, effort) = (model.to_owned(), effort.to_owned());
        let serve = async move {
            let mut posted = false;
            let mut connections = 0;
            loop {
                // Drain already queued connections at finish; a duplicate POST must not race closure.
                let (mut socket, peer) = tokio::select! { biased;
                    accepted = listener.accept() => accepted?,
                    _ = &mut closed => break,
                    rejected = deny.accept() => {
                        // Never read, resolve, or forward the rejected target.
                        drop(rejected?);
                        continue;
                    }
                };
                connections += 1;
                ensure!(
                    peer.ip().is_loopback() && connections <= 32,
                    "unexpected OMP probe connection"
                );
                // One active socket, one bounded request per socket, no detached handlers.
                timeout(Duration::from_secs(5), async {
                    match receive(&mut socket, &authority, mode, &model, &effort, &mut posted).await
                    {
                        Ok((status, mime, data)) => send(&mut socket, status, mime, &data).await,
                        Err(error) => {
                            let _ = send(
                                &mut socket,
                                "403 Forbidden",
                                "application/json",
                                r#"{"error":"probe denied request"}"#,
                            )
                            .await;
                            Err(error)
                        }
                    }
                })
                .await
                .context("OMP probe socket timed out")??;
            }
            #[cfg(feature = "omp-go-fixture")]
            let expected_post = !matches!(mode, Case::RejectAuth);
            #[cfg(not(feature = "omp-go-fixture"))]
            let expected_post = true;
            ensure!(posted == expected_post, "unexpected OMP probe POST count");
            Ok(())
        };
        let task = tokio::spawn(async move {
            timeout(Duration::from_secs(120), serve)
                .await
                .context("OMP probe window expired")?
        });
        Ok(Self {
            origin,
            proxy,
            close: Some(close),
            task,
        })
    }

    pub(super) fn origin(&self) -> &str {
        &self.origin
    }

    pub(super) fn proxy(&self) -> &str {
        &self.proxy
    }

    pub(super) async fn finish(mut self) -> Result<()> {
        drop(self.close.take());
        (&mut self.task).await.context("joining OMP probe")?
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type Reply = (&'static str, &'static str, String);

async fn receive(
    socket: &mut TcpStream,
    authority: &str,
    mode: Case,
    model: &str,
    effort: &str,
    posted: &mut bool,
) -> Result<Reply> {
    let mut reader = BufReader::new(socket);
    let mut headers = String::new();
    {
        let mut bounded = (&mut reader).take(16 * 1024);
        while !headers.ends_with("\r\n\r\n") {
            ensure!(
                bounded.read_line(&mut headers).await? != 0,
                "incomplete or oversized OMP probe headers"
            );
        }
    }
    let mut lines = headers.split("\r\n");
    let (route, version) = lines
        .next()
        .and_then(|line| line.rsplit_once(' '))
        .context("invalid OMP probe request line")?;
    ensure!(
        matches!(version, "HTTP/1.0" | "HTTP/1.1"),
        "unsupported OMP probe HTTP version"
    );
    let listing = match route {
        "GET /v1/models" => true,
        "POST /v1/chat/completions" => {
            ensure!(!*posted, "OMP attempted a second chat completion POST");
            *posted = true; // Count the first attempt before validation, including a downgraded effort.
            false
        }
        _ => bail!("OMP attempted a non-fixture route"),
    };
    let (mut host, mut length, mut authorization) = (None, None, None);
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').context("invalid OMP probe header")?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            ensure!(host.replace(value).is_none(), "duplicate OMP probe Host");
        } else if name.eq_ignore_ascii_case("content-length") {
            ensure!(
                length.replace(value.parse::<usize>()?).is_none(),
                "duplicate OMP probe Content-Length"
            );
        } else if name.eq_ignore_ascii_case("authorization") {
            ensure!(
                authorization.replace(value).is_none(),
                "duplicate OMP probe Authorization"
            );
        } else {
            ensure!(
                !name.eq_ignore_ascii_case("transfer-encoding"),
                "unsupported OMP probe framing"
            );
        }
    }
    ensure!(host == Some(authority), "nonlocal OMP probe Host");
    if listing {
        ensure!(
            length.unwrap_or(0) == 0 && reader.buffer().is_empty(),
            "unexpected OMP discovery data"
        );
        // Identity-only native row: do not advertise effort, API, compatibility or routing settings.
        let data = json!({"object":"list","data":[{"object":"model","id":model}]});
        return Ok(("200 OK", "application/json", data.to_string()));
    }
    ensure!(
        authorization.and_then(|value| value.strip_prefix("Bearer ")) == Some(FIXTURE_KEY),
        "unexpected OMP probe authorization"
    );
    let length = length.context("OMP probe POST requires Content-Length")?;
    ensure!(
        (1..=64 * 1024).contains(&length),
        "unexpected OMP probe body size"
    );
    let mut body = vec![0; length];
    reader.read_exact(&mut body).await?;
    ensure!(reader.buffer().is_empty(), "pipelined OMP probe request");
    validate(&serde_json::from_slice(&body)?, model, effort)?;
    match mode {
        #[cfg(feature = "omp-go-fixture")]
        Case::RejectAuth => bail!("OMP sent a POST after synthetic auth refusal"),
        Case::RejectEffort => {
            let offered = match effort {
                "max" => "high",
                "medium" => "low",
                _ => "medium",
            };
            let requested = if effort == "off" { "none" } else { effort };
            let message = format!(
                "Unsupported reasoning_effort '{requested}'. Supported values are: '{offered}'."
            );
            let data = json!({"error":{"type":"invalid_request_error","param":"reasoning_effort","message":message}});
            Ok(("400 Bad Request", "application/json", data.to_string()))
        }
        Case::Capture => Ok(("200 OK", "text/event-stream", completion(model, model))),
        Case::RejectServedModel => {
            let other = if model == "fixture/other" {
                "fixture/different"
            } else {
                "fixture/other"
            };
            // A later echo of the requested model must not erase the first contradiction.
            Ok(("200 OK", "text/event-stream", completion(other, model)))
        }
    }
}

fn text(message: &Value) -> Option<&str> {
    if message
        .as_object()?
        .keys()
        .any(|k| !matches!(k.as_str(), "role" | "content" | "cache_control"))
    {
        return None;
    }
    let content = message.get("content")?;
    if let Some(text) = content.as_str() {
        return Some(text);
    }
    let [part] = content.as_array()?.as_slice() else {
        return None;
    };
    if part["type"] == "text"
        && part
            .as_object()?
            .keys()
            .all(|k| matches!(k.as_str(), "type" | "text" | "cache_control"))
    {
        part["text"].as_str()
    } else {
        None
    }
}

fn validate(body: &Value, model: &str, effort: &str) -> Result<()> {
    ensure!(
        body["model"] == model && body["stream"] == true,
        "OMP did not request the exact streaming model"
    );
    let actual = body.get("reasoning_effort");
    let expected = if effort == "off" { "none" } else { effort };
    ensure!(
        actual.and_then(Value::as_str) == Some(expected) || (effort == "off" && actual.is_none()),
        "OMP first POST sent reasoning_effort={}, expected {effort}",
        actual
            .and_then(Value::as_str)
            .filter(|s| s.len() <= 16 && s.bytes().all(|b| b.is_ascii_lowercase()))
            .unwrap_or("<absent or invalid>")
    );
    for key in ["tools", "functions", "plugins", "fallbacks"] {
        ensure!(
            body.get(key)
                .is_none_or(|v| v.as_array().is_some_and(Vec::is_empty)),
            "OMP probe enabled extensions to the native request"
        );
    }
    ensure!(
        body.get("web_search_options").is_none_or(Value::is_null),
        "OMP probe enabled web search"
    );
    for key in ["tool_choice", "function_call"] {
        ensure!(
            body.get(key).is_none_or(|v| v.is_null()
                || v == "none"
                || (v["type"] == "none" && v.as_object().is_some_and(|o| o.len() == 1))),
            "OMP probe selected a tool"
        );
    }
    let messages = body["messages"]
        .as_array()
        .context("missing OMP probe messages")?;
    let [policy, user] = messages.as_slice() else {
        bail!("unexpected OMP probe history");
    };
    ensure!(
        matches!(policy["role"].as_str(), Some("system" | "developer"))
            && text(policy) == Some(POLICY)
            && user["role"] == "user",
        "OMP probe policy and user data were not isolated"
    );
    let data: Value = serde_json::from_str(text(user).context("OMP probe user data is not text")?)?;
    ensure!(
        data == json!({"kind":"answer","request":{"kind":"answer","probe":REQUEST_MARKER}}),
        "OMP probe user data changed"
    );
    Ok(())
}

fn completion(first_model: &str, model: &str) -> String {
    let chunk = |model: &str, choices: Value, usage: Value| {
        json!({"id":"chatcmpl-agmi-probe","created":1,
        "object":"chat.completion.chunk","model":model,"choices":choices,"usage":usage})
    };
    let text = chunk(
        first_model,
        json!([{"index":0,"delta":{"role":"assistant","content":OUTPUT},"finish_reason":null}]),
        Value::Null,
    );
    let stop = chunk(
        model,
        json!([{"index":0,"delta":{},"finish_reason":"stop"}]),
        Value::Null,
    );
    let usage = chunk(
        model,
        json!([]),
        json!({"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}),
    );
    format!("data: {text}\n\ndata: {stop}\n\ndata: {usage}\n\ndata: [DONE]\n\n")
}

async fn send(socket: &mut TcpStream, status: &str, mime: &str, data: &str) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        data.len()
    );
    socket.write_all(head.as_bytes()).await?;
    socket.write_all(data.as_bytes()).await?;
    Ok(())
}
