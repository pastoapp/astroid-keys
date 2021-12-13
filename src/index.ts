import {
  generateKeyPair as gKeyPair,
  getKeyPairFromMnemonic as gMemPair,
} from 'human-crypto-keys';
import { IHumanCryptoKey } from './interfaces/IHumanCryptoKey.interface';
import {
  createSign,
  createVerify,
  publicEncrypt,
  privateDecrypt,
} from 'crypto';

/**
 * Generate a key pair with the RSA algorithm. The key pair is generated with the default key size of 2048 bits.
 * RSA is used because elliptic curve cryptography is currently not supported by node.js (14 LTS).
 */
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

/**
 * Signs a message with the private key.
 * @param message message to be signed
 * @param privateKey corresponding (RSA) private key
 * @returns {Promise<string>} signature
 */
export const signMessage = async (
  message: string,
  privateKey: string
): Promise<string> => {
  const signer = createSign('RSA-SHA256');
  signer.update(message);
  return signer.sign(privateKey, 'base64');
};

/**
 * Verifies a signature with the public key.
 * @param message message to be verified
 * @param signature signature to be verified
 * @param publicKey corresponding (RSA) public key
 * @returns {Promise<boolean>} true if the signature is valid
 */
export const verifyMessage = async (
  message: string,
  signature: string,
  publicKey: string
): Promise<boolean> => {
  const verifier = createVerify('RSA-SHA256');
  verifier.update(message);
  return verifier.verify(publicKey, signature, 'base64');
};

/**
 * encrypts a message with the public key.
 * @param message message to be encrypted
 * @param publicKey public key to encrypt with
 * @returns encrypted message
 */
export const encryptMessage = async (message: string, publicKey: string) => {
  const encrypted = publicEncrypt(publicKey, Buffer.from(message));
  return encrypted.toString('base64');
};

/**
 * decrypts a message with the private key.
 * @param encryptMessage encrypted message
 * @param privateKey private key to decrypt with
 * @returns decrypted message
 */
export const decryptMessage = async (
  encryptMessage: string,
  privateKey: string
) => {
  const decrypted = Buffer.from(encryptMessage, 'base64');
  const decryptedMessage = privateDecrypt(privateKey, decrypted);
  return decryptedMessage.toString();
};
