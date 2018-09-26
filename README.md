# BlockOTP
BlockOTP is a Blockchain-Based One-Time Password Setup Using Newly Minted Blocks and Json Web Tokens

## Overview

* Blockchain Height Data Encoded in JWT Format
  * Authentication token expires after block height + (N) blocks

* Blockchain Desync Guard with Transaction Merkle Root
  * Merkle root data of block height pulled from https://rest.bitcoin.com

* JWT Payload Details Auth Token Expiration Via New Block Heights
  * Token initialized through current block height && merkle root, expiring at a future block height

## Environment Configuration
Env data currently stores the secrets for the signature. Currently, any secret works for the signing

## Setup

```
npm install ( OR ) yarn install
```

## Start

```
npm run start ( OR ) yarn start
```

## Development
Currently developing on JWT responses
```
npm run dev ( OR ) yarn dev
```

## Build

```
npm run build ( OR ) yarn build
```

## Lint

```
npm run lint ( OR ) yarn lint
```

## Package Audit with snyk

```
npm run audit ( OR ) yarn audit
```

## Test

```
npm run test ( OR ) yarn test
```
