# Partially working. Unfinished

> [!IMPORTANT]  
> Add the required env variables in [config.toml](.cargo/config.toml) before building.

## Build targets
MacOS (ARM)
```zsh
cargo b -r --target aarch64-apple-darwin
```
Linux (x64)
```zsh
cargo b -r --target x86_64-unknown-linux-musl
```

## TODO

- [x] Successfully build a release version for x86_64 linux
- [ ] Finish the api server.
- [ ] Finish socket server.
- [ ] Implement proper data encryption.
- [ ] Write a full README.
