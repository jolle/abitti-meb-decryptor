import yauzl from 'yauzl';
import { pbkdf2Sync, createDecipheriv, createVerify } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';

export interface DecryptedMeb {
  exam: {
    examUuid: string;
    content: {
      title: string;
      instruction: string;
      sections: any[];
      schemaVersion: '1.0';
      hasAttachments: boolean;
    };
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

const readZip = (file: Buffer) =>
  new Promise<{ [filename: string]: Buffer }>((resolve, reject) =>
    yauzl.fromBuffer(file, { lazyEntries: true }, (err, zipFile) => {
      if (err) return reject(err);
      if (!zipFile) return reject(Error('Failed to read the MEB file'));

      const entries: { [filename: string]: Buffer } = {};

      zipFile.readEntry();
      zipFile.on('entry', (entry) => {
        if (/\/$/.test(entry.fileName)) {
          zipFile.readEntry();
        } else {
          zipFile.openReadStream(entry, (err, readStream) => {
            if (err) return reject(err);
            if (!readStream)
              return reject(Error('Failed to read the MEB file (2)'));

            const dataPieces: Buffer[] = [];
            readStream.on('end', () => {
              entries[entry.fileName] = Buffer.concat(dataPieces);

              zipFile.readEntry();
            });
            readStream.on('data', (data) => {
              dataPieces.push(data);
            });
          });
        }
      });
      zipFile.on('end', () => {
        resolve(entries);
      });
    })
  );

const deriveKeyAndIv = (password: string) => {
  const trimmedPassword = password.replace(/\s/g, '');
  const derivedData = pbkdf2Sync(
    trimmedPassword,
    trimmedPassword,
    2000,
    32 + 16,
    'SHA1'
  );
  const key = derivedData.slice(0, 32);
  const iv = derivedData.slice(32, 48);
  return { key, iv };
};

const decrypt = (content: Buffer, password: string) => {
  const { key, iv } = deriveKeyAndIv(password);
  const decipher = createDecipheriv('aes-256-ctr', key, iv);

  return Buffer.concat([decipher.update(content), decipher.final()]);
};

const verifySignature = (
  encrypted: Buffer,
  signature: Buffer,
  publicKey: Buffer
) => {
  const verifier = createVerify('RSA-SHA256');
  verifier.update(encrypted);

  return verifier.verify(publicKey, signature.toString('utf8'), 'base64');
};

export const decryptMeb = async (
  mebFile: Buffer,
  password: string,
  signaturePublicKey?: Buffer
): Promise<DecryptedMeb> => {
  const files = await readZip(mebFile);

  if (signaturePublicKey) {
    for (let fileName in files) {
      if (fileName.endsWith('.sig')) continue;

      const signature = files[`${fileName}.sig`];
      if (
        signature &&
        !verifySignature(files[fileName], signature, signaturePublicKey)
      )
        throw Error(`Invalid signature for file ${fileName}`);
    }
  }

  const decryptedFiles = Object.entries(files)
    .filter(([fileName]) => fileName.endsWith('.bin'))
    .map(
      ([fileName, content]) =>
        [fileName.replace(/\.bin$/, ''), decrypt(content, password)] as [
          string,
          Buffer
        ]
    )
    .reduce(
      (p, n) => ({ ...p, [n[0]]: n[1] }),
      {} as { [fileName: string]: Buffer }
    );

  const examJson = decryptedFiles['exam.json'];
  if (!examJson) throw Error('Exam file missing');
  if (!examJson.toString().startsWith('{"'))
    throw Error('Invalid passphrase/decryption key');

  return {
    exam: JSON.parse(examJson.toString()),
    files: decryptedFiles as {
      'exam.json': Buffer;
      'nsa.zip': Buffer;
      [fileName: string]: Buffer;
    },
  };
};
