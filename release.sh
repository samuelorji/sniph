cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin

lipo -create \
  target/x86_64-apple-darwin/release/sniph \
  target/aarch64-apple-darwin/release/sniph \
  -output sniph

tar -czf sniph-mac.tar.gz sniph

sha_sum=$(shasum -a 256 sniph-mac.tar.gz)
echo $sha_sum

tag=$1
gh release create "v$tag" ./sniph-mac.tar.gz \
 --title "Release v${tag}" \


