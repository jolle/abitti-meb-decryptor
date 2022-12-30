import { join } from "path";
import { readFileSync } from "fs";
import { decryptExamFile, FilesWithExamJson } from "../src";

const PASSWORD = "syyssade kumaruus tyvivesa uurros";

describe("MEB", () => {
  it("decrypts a MEB file successfully", async () => {
    const output = await decryptExamFile(
      readFileSync(join(__dirname, "exam_Uusi_koe_mex.meb")),
      PASSWORD
    );

    expect("exam.json" in output).toBe(true);

    const examWithJson = output as FilesWithExamJson;

    expect(examWithJson["exam.json"]).toBeInstanceOf(Buffer);
    expect(examWithJson["nsa.zip"]).toBeInstanceOf(Buffer);

    const parsedExam = JSON.parse(examWithJson["exam.json"].toString());

    expect(parsedExam.password).toBe(PASSWORD);
  });
});
