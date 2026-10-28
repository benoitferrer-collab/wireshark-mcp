Public demonstration captures and secrets from the official Wireshark test suite:
https://github.com/wireshark/wireshark/tree/master/test

Mapping: tls13 = tls13-rfc8446.pcap/.keys; rsa = rsasnakeoil2.pcap/.key;
http2 = http2-data-reassembly.pcap/.keys. The RSA key here is public test material,
never a production credential. These fixtures are excluded from Vercel uploads.
