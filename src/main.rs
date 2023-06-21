use log;
use std::env;
use std::process;

use jwt_getter_lib::get_jwt;

static URL: &str = "http://localhost:8080";
static SCOPE_T: &str = "security.ts.bfc8.tokenization";
static SCOPE_D: &str = "security.ts.bfc8.detokenization";

#[tokio::main]
async fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Help: jwt_getter T|D [url]");
        process::exit(1);
    }

    let s = &args[1];
    let scope: &str;
    if s.eq_ignore_ascii_case("T") {
        scope = SCOPE_T;
    } else if s.eq_ignore_ascii_case("D") {
        scope = SCOPE_D;
    } else {
        log::error!("Invalid scope: {s}");
        process::exit(1);
    }

    let url: &str;
    if args.len() == 3 {
        url = &args[2];
    } else {
        url = URL;
    }

    log::info!("calling lib");
    let result = match get_jwt(scope, url).await {
        Ok(token) => token,
        Err(e) => {
            log::error!("Error: {e}");
            String::new()
        }
    };

    println!("{result}");
}
