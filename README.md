# abitti-meb-decryptor

Decrypts meb files that are generated by the oma.abitti.fi service and used by the Abitti examination OS.

## Example

```ts
import { decryptMeb } from 'abitti-meb-decryptor';
import { readFileSync } from 'fs';

console.log(
  decryptMeb(readFileSync('my-exam-file.meb'), 'my super secure passphrase')
);
```

## Usage

### `async decryptMeb(mebFile: Buffer, password: string, signaturePublicKey?: Buffer) ⇒ DecryptedMeb`

Decrypts the given meb file with the given password. The signature will be validated with a public key if a public key is given. If no public key is given, signature checking is skipped.

### `DecryptedMeb`

```ts
interface DecryptedMeb {
  exam: {
    examUuid: string;
    content: any;
    answerEmailsSent: null | any;
    locked: boolean;
    password: string;
    accessible: boolean;
    attachmentsFileName: string | null;
  };
  files: {
    'exam.json': Buffer;
    'nsa.zip': Buffer;
    [fileName: string]: Buffer;
  };
}
```
