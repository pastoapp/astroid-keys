import {
  generateKeyPair as gKeyPair,
  getKeyPairFromMnemonic as gMemPair,
} from 'human-crypto-keys';
import { IHumanCryptoKey } from './interfaces/IHumanCryptoKey.interface';
import { createSign, createVerify } from 'crypto';

export const ALGORITHM = 'rsa';

/**
 * Generates a key pair with rsa encryption and provides information for recovery.
 * @returns {Promise<IHumanCryptoKey>} containing the public and private key, as well as the algorithm  and mnemonic used
 */
export const generateKeyPair = async (): Promise<IHumanCryptoKey> => {
  return await gKeyPair(ALGORITHM);
};

/**
 * Generates the same key pair based on the mnemonic.
 * @param mnemonic mnemonic phrase
 * @returns {Promise<IHumanCryptoKey>} contains the private key and public key
 */
export const generateKeyPairFromMnemonic = async (
  mnemonic: string
): Promise<IHumanCryptoKey> => {
  return await gMemPair(mnemonic, ALGORITHM);
};

export const signMessage = async (
  message: string,
  privateKey: string
): Promise<string> => {
  const signer = createSign('RSA-SHA256');
  signer.update(message);
  return signer.sign(privateKey, 'base64');
};

export const verifyMessage = async (
  message: string,
  signature: string,
  publicKey: string
): Promise<boolean> => {
  const verifier = createVerify('RSA-SHA256');
  verifier.update(message);
  return verifier.verify(publicKey, signature, 'base64');
};
