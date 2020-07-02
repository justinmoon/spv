Compile [this RP](https://github.com/bitcoin/bitcoin/pull/18876)

```
git clone git@github.com:bitcoin/bitcoin.git
cd bitcoin
git fetch origin pull/16442/head:bip157
git checkout bip157
./autogen.sh
./configure
make
```
(I had to run `./autogen.sh --with-incompatible-bdb` for some reason ...)

Run bitcoind:

```
./src/bitcoind -regtest -blockfilterindex -peercfilters=1
```

Tips:
- Add a `-daemon` flab to run in background
- Add a `-debug` flab to see more logging information (helpful for debugging why bitcoind rejects bad requests)

Mine yourself some blocks:
```
$ CORE_ADDR=$(bitcoin-cli -regtest getnewaddress)
$ bitcoin-cli -regtest generatetoaddress 101 $CORE_ADDR
```

Create a watch-only wallet (easy way to test out wallet tracking)

```
$ bitcoin-cli -regtest createwallet spv
$ SPV_ADDR=$(bitcoin-cli -rpcwallet=spv -regtest getnewaddress)
$ echo $SPV_ADDR
bcrt1q9carqaysp57tz4j55lj7mms09r65vn80qmaq2j
```

Write that address down somewhere.

Send it 1 bitcoin, and mine a block to confirm the transaction.

```
$ bitcoin-cli -rpcwallet=spv -regtest sendtoaddress $SPV_ADDR 1
$ bitcoin-cli -regtest generatetoaddress 1 $CORE_ADDR
```

Run this project:

```
$ cargo run regtest 127.0.0.1:18444 $SPV_ADDR
...
100000000
...
```

You should see a 1 BTC balance displayed (as satoshis)

Send some coins back to the default wallet

```
bitcoin-cli -rpcwallet="spv" -regtest sendtoaddress $CORE_ADDR 1
bitcoin-cli -regtest generatetoaddress 1 $CORE_ADDR
```

Run the project again and you should see an updated balance logged.

This isn't perfect ...
