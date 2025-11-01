use bytes::Bytes;
use futures_util::Stream;
use reqwest::Client;
use std::pin::Pin;
use std::task::{Context, Poll};

pub enum SseEvent {
    Message(String),
    Heartbeat,
}

pub struct SseStream {
    lines: LineStream,
}

struct LineStream {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>,
    buffer: String,
}

impl LineStream {
    fn new(stream: impl Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static) -> Self {
        Self {
            inner: Box::pin(stream),
            buffer: String::new(),
        }
    }
}

impl Stream for LineStream {
    type Item = Result<String, reqwest::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(pos) = this.buffer.find('\n') {
                let mut line = this.buffer[..pos].to_string();
                this.buffer.drain(..=pos);
                if line.ends_with('\r') {
                    line.pop();
                }
                return Poll::Ready(Some(Ok(line)));
            }

            match futures_util::ready!(this.inner.as_mut().poll_next(cx)) {
                Some(Ok(chunk)) => {
                    this.buffer.push_str(&String::from_utf8_lossy(&chunk));
                }
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => {
                    if this.buffer.is_empty() {
                        return Poll::Ready(None);
                    } else {
                        let line = std::mem::take(&mut this.buffer);
                        return Poll::Ready(Some(Ok(line)));
                    }
                }
            }
        }
    }
}

impl Stream for SseStream {
    type Item = Result<SseEvent, reqwest::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match futures_util::ready!(Pin::new(&mut this.lines).poll_next(cx)) {
            Some(Ok(line)) => {
                if line.trim().is_empty() || line.starts_with(':') {
                    Poll::Ready(Some(Ok(SseEvent::Heartbeat)))
                } else {
                    Poll::Ready(Some(Ok(SseEvent::Message(line.trim().to_string()))))
                }
            }
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

pub async fn connect_sse(client: &Client, url: &str) -> Result<SseStream, reqwest::Error> {
    let resp = client.get(url).send().await?;
    let resp = resp.error_for_status()?;
    let byte_stream = resp.bytes_stream();

    Ok(SseStream {
        lines: LineStream::new(byte_stream),
    })
}
