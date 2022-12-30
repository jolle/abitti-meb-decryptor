import { join } from "path";
import { readFileSync } from "fs";
import { decryptExamFile, FilesWithExamXml } from "../src";

const PASSWORD = "sokeutua jiddi ingressi iltanen";

describe("MEX", () => {
  it("decrypts a MEX file successfully", async () => {
    const output = await decryptExamFile(
      readFileSync(join(__dirname, "exam_Uusi_koe.mex")),
      PASSWORD
    );

    expect("exam.xml" in output).toBe(true);

    const examWithXml = output as FilesWithExamXml;

    expect(examWithXml["exam.xml"]).toBeInstanceOf(Buffer);
    expect(examWithXml["nsa.zip"]).toBeInstanceOf(Buffer);

    expect(examWithXml["exam.xml"].toString()).toContain('exam-lang="fi-FI"');
  });
});
