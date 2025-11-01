use futures_util::stream::StreamExt;
use reqwest_eventsource::{Event, EventSource};

#[tokio::main]
async fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "http://127.0.0.1:3000/alerts".into());
    let mut es = EventSource::get(url);
    while let Some(event) = es.next().await {
        match event {
            Ok(ev) => match ev {
                Event::Open => eprintln!("connected"),
                Event::Message(msg) => println!("{}", msg.data),
            },
            Err(e) => {
                eprintln!("error: {e}");
                break;
            }
        }
    }
}
