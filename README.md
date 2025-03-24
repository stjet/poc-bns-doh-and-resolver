This is a merely Proof of Concept!

DoH (DNS over HTTPS) requires the HTTPS part. So, locally generate a SSL certificate for `localhost`. Make sure you understand the security implications of this!

```
git clone https://github.com/stjet/poc-bns-doh-and-resolver
cd poc-bns-doh-and-resolver
mkcert -install
mkcert 127.0.0.1 "*.ban.k" "*.jtv.k" "*.mictest.k"
```

Then run:

```
cargo build --release
sudo ROCKET_PROFILE=debug ./target/release/bns-doh-and-resolver
```

In your browser's DoH settings, set it to the URL `https://127.0.0.1/dns-query`. Try going to [http://prussia.ban](http://prussia.ban), or for HTTPS, go to [https://prussia.ban.k](https://prussia.ban.k).
