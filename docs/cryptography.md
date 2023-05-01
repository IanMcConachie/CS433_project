# Cryptography docs

## Choice of protocol

For this project we want to use a symmetric encryption scheme where the secret key is only held by our server. In researching different options for symmetric cryptosystems we landed on using AES (Rijndael) with a 256 bit key. The current secure AES-256 cryptosystem arranges messages in a 4x4 byte matrix and performs 14 rounds of encryption in order to generate cipher text. In each round bytes are substituted, shifted row-by-row, multiplied with a polynomial column-by-column, and XORed with a subkey derived from the original secret key. The diagram below shows the encryption flow for each round.

<img src="./imgs/Rijndael.png" style="height: 400px;">

<!--![Rijndael Diagram](./imgs/Rijndael.png)-->

## Justification

The AES-256 protocol was chosen because it is secure against the majority of attacks and is ubiquitous in cybersecurity practice. 


## Implementation of protocol

This protocol will be implemented in Python using the AES class from the popular Python cryptography library PyCryptodome.

## References

- Daemen, J., & Rijmen, V. (1999). AES proposal: Rijndael.
- https://github.com/Legrandin/pycryptodome




# TODO

- Include some cryptanalysis about how long it would take to crack in **Justification**