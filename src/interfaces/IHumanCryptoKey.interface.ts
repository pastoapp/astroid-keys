export interface IHumanCryptoKey {
  algorithm: Algorithm;
  mnemonic: string;
  seed: { [key: string]: number };
  privateKey: string;
  publicKey: string;
}

export interface Algorithm {
  id: string;
}
