import { generateKeyPair, generateKeyPairFromMnemonic } from '../src/index';
describe('testing human crypto keys', () => {
  it('test if keys are existent', async () => {
    const response = await generateKeyPair();
    expect(response.privateKey).toBeDefined();
    expect(response.publicKey).toBeDefined();
    expect(response.algorithm).toBeDefined();
    expect(response.mnemonic).toBeDefined();
    expect(response.seed).toBeDefined();
  });

  it('test if keys are deterministically generated from a seed', async () => {
    const mnemonic =
      'solid sudden face start day confirm thought tag cram indicate museum civil';

    const keyPair = {
      privateKey:
        '-----BEGIN PRIVATE KEY-----\n' +
        'MC4CAQAwBQYDK2VwBCIEIBgrnnyGTg/yhRW0dL+wgRc+DYa9hAb65PBOjenXFJc4\n' +
        '-----END PRIVATE KEY-----\n',
      publicKey:
        '-----BEGIN PUBLIC KEY-----\n' +
        'MCowBQYDK2VwAyEA11H0LJU9gn2KiGshpD8C2+dMP6chBAOsFK7zH2XORyc=\n' +
        '-----END PUBLIC KEY-----\n',
    };

    const response = await generateKeyPairFromMnemonic(mnemonic);

    expect(response.privateKey).toEqual(keyPair.privateKey);
    expect(response.publicKey).toEqual(keyPair.publicKey);
  });
});
