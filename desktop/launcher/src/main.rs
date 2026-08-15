fn main() {
    if let Err(error) = js_agent_host_launcher::launch() {
        eprintln!("js-agent-host: {}", error.code());
        std::process::exit(64);
    }
}
