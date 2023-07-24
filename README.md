This code is based on "Collusion Resistant Broadcast Encryption With
Short Ciphertexts and Private Keys" paper [BGW05](https://eprint.iacr.org/2005/018.pdf) by Dan Boneh

# install
```
npm i
```

# test
```
npm test
```
# Overview

This is just a POC of an earlier version of broadcast based encryption by Dan Boneh et al. We need something much better for Farcaster.

* setup a channel of `n` users, runtime and public key size linear with `n` (96 bytes per user.)
* create a random subset `S` of users that will be allowed to decrypt.
* create a random encryption key `K` and encrypt it. Runtime linear with `|S|`
* select random users and check that only users in `S` can decrypt and retrieve `K`. Run time linear with `|S|` (4usec per user)


This construction splits the users into shards of size `m` and splitting `S` accordingly. You can use the same public key in each shard except for a different `gamma`in each shard. So now all sizes are proportional to the shard size.



