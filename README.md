# Json Web Token Getter

This a command line utility written in Rust. It is supposed to work wtih the [jwt_issuer](https://github.com/pheely/jwt_issuer). 

It passes a client JWT and a specific scope (tokenization or detokenization) as the request payload. Upon receiving the request, the `jwt_issue` will issue a JWT with the appropriate scope.

## Build the binary

```bash
cargo build --release
```

## Run

For tokenization:

```bash
./target/release/jwt_getter T
```

For detokenization:

```bash
./target/release/jwt_getter D
```

The default jwt issuer is https://localhost:8080. For a different server, specify the url as the second parameter.

## Logging level

There is no log by default. To set a logging level, use the `RUST_LOG` environment variable. For example, to  turn on the debug log, 

```bash
RUST_LOG=debug ./target/release/jwt_getter T
```

## Development

The following VS Code plugins are required.

- rust-analyzer
- better toml
- crates
- error lens
- codelldb

To debug the code, build the code first and update the `launch.json` with the right path to the binary under `program`.

```bash
cargo build -v
```

Here is a sample `launch.json`:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "lldb",
            "request": "launch",
            "name": "rust is fun",
            "program": "${workspaceRoot}/target/debug/jwt_getter",
            "args": ["T"],
            "cwd": "${workspaceRoot}",
            "sourceLanguages": ["rust"]
        }
    ]
}
```