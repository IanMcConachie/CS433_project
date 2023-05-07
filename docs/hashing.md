# Hashing docs

## Choice of protocol

For the image hashing that is involved in generating our digital image watermarks we decided to use the SHA-256 protocol.

## Justification

Our hashing does not necessarily need to be cryptographically secure because the security of our system does not depend on the hashing function being robust against attacks. Instead the hashing function just acts as a convenient way to associate a watermark with specific images so that watermarks can't be extracted and reused by potential attackers.

SHA-256 was selected because it has the benefits that we usually look for in hashing functions--ie, the output is of constant length, the hashing algorithm is fast, and collision is very unlikely. It is also a well-documented, popular algorithm which made finding a Python library that implements it much easier.

## Implementation of protocol

To perform the actual SHA-256 algorithm we use the default `hashlib` library provided by Python. This choice was made because we want the most optimized code for hashing in order to reduce the amount of time it takes to watermark and verify images.