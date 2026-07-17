use std::io;

fn parse_request(input: &str) -> Option<String> {
    validate_input(input)
}

fn validate_input(data: &str) -> Option<String> {
    if data.is_empty() {
        None
    } else {
        Some(data.to_string())
    }
}

fn main() {
    let _ = parse_request("test");
}
