import yauzl from "yauzl";
import { pbkdf2Sync, createDecipheriv, createVerify } from "crypto";

interface BaseFiles {
  "nsa.zip"?: Buffer;
  "attachments.zip"?: Buffer;
  "koe-update.zip"?: Buffer;
  "rendering.zip"?: Buffer;
  [fileName: string]: Buffer | undefined;
}

export type FilesWithExamJson = BaseFiles & { "exam.json": Buffer };
export type FilesWithExamXml = BaseFiles & { "exam.xml": Buffer };

export type DecryptedFiles = FilesWithExamJson | FilesWithExamXml;

const readZip = (file: Buffer) =>
  new Promise<{ [filename: string]: Buffer }>((resolve, reject) =>
    yauzl.fromBuffer(file, { lazyEntries: true }, (err, zipFile) => {
      if (err) return reject(err);
      if (!zipFile) return reject(Error("Failed to read the MEB file"));

      const entries: { [filename: string]: Buffer } = {};

      zipFile.readEntry();
      zipFile.on("entry", (entry) => {
        if (/\/$/.test(entry.fileName)) {
          zipFile.readEntry();
        } else {
          zipFile.openReadStream(entry, (err, readStream) => {
            if (err) return reject(err);
            if (!readStream)
              return reject(Error("Failed to read the MEB file (2)"));

            const dataPieces: Buffer[] = [];
            readStream.on("end", () => {
              entries[entry.fileName] = Buffer.concat(dataPieces);

              zipFile.readEntry();
            });
            readStream.on("data", (data) => {
              dataPieces.push(data);
            });
          });
        }
      });
      zipFile.on("end", () => {
        resolve(entries);
      });
    }),
  );

const deriveKeyAndIv = (password: string) => {
  const trimmedPassword = password.replace(/\s/g, "");

  const derivedData = pbkdf2Sync(
    trimmedPassword,
    trimmedPassword,
    2000,
    32 + 16,
    "SHA1",
  );

  const key = derivedData.slice(0, 32);
  const iv = derivedData.slice(32, 48);

  return { key, iv };
};

const decrypt = (content: Buffer, password: string) => {
  const { key, iv } = deriveKeyAndIv(password);
  const decipher = createDecipheriv("aes-256-ctr", key, iv);

  return Buffer.concat([decipher.update(content), decipher.final()]);
};

const verifySignature = (
  encrypted: Buffer,
  signature: Buffer,
  publicKey: Buffer,
) => {
  const verifier = createVerify("RSA-SHA256");
  verifier.update(encrypted);

  return verifier.verify(publicKey, signature.toString("utf8"), "base64");
};

/**
 * Decrypts the exam file and returns the inner files without
 * checking that an exam file exists.
 *
 * @param encryptedFile the contents of the encrypted MEB/MEX file
 * @param password the passphrase for the exam file
 * @param signaturePublicKey the public key for verifying the exam file
 * @returns an object with the files inside the exam file zip
 */
export const decryptExamFileRaw = async (
  encryptedFile: Buffer,
  password: string,
  signaturePublicKey?: Buffer,
): Promise<Record<string, Buffer>> => {
  const files = await readZip(encryptedFile);

  if (signaturePublicKey) {
    for (let fileName in files) {
      if (fileName.endsWith(".sig")) continue;

      const signature = files[`${fileName}.sig`];
      if (
        signature &&
        !verifySignature(files[fileName], signature, signaturePublicKey)
      )
        throw Error(`Invalid signature for file ${fileName}`);
    }
  }

  const decryptedFiles = Object.fromEntries(
    Object.entries(files)
      .filter(([fileName]) => fileName.endsWith(".bin"))
      .map(
        ([fileName, content]) =>
          [fileName.replace(/\.bin$/, ""), decrypt(content, password)] as [
            string,
            Buffer,
          ],
      ),
  );

  return decryptedFiles;
};

/**
 * Decrypts the exam file and returns the inner files ensuring that
 * a valid exam file is found.
 *
 * @param encryptedFile the contents of the encrypted MEB/MEX file
 * @param password the passphrase for the exam file
 * @param signaturePublicKey the public key for verifying the exam file
 * @returns the decrypted inner exam files
 */
export const decryptExamFile = async (
  encryptedFile: Buffer,
  password: string,
  signaturePublicKey?: Buffer,
): Promise<DecryptedFiles> => {
  const decryptedFiles = await decryptExamFileRaw(
    encryptedFile,
    password,
    signaturePublicKey,
  );

  if ("exam.json" in decryptedFiles) {
    if (!decryptedFiles["exam.json"].toString().startsWith('{"')) {
      throw new Error("Invalid passphrase/decryption key");
    }

    return decryptedFiles as FilesWithExamJson;
  } else if ("exam.xml" in decryptedFiles) {
    if (!decryptedFiles["exam.xml"].toString().startsWith("<?xml")) {
      throw new Error("Invalid passphrase/decryption key");
    }

    return decryptedFiles as FilesWithExamXml;
  }

  throw new Error("Exam file missing");
};
