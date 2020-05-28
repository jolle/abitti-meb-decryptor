import { join } from 'path';
import { readFileSync } from 'fs';
import { decryptMeb } from '../src';

const PASSWORD = 'syyssade kumaruus tyvivesa uurros';

describe('MEB', () => {
  it('decrypts a MEB file successfully', async () => {
    const output = await decryptMeb(
      readFileSync(join(__dirname, 'exam_Uusi_koe_mex.meb')),
      PASSWORD
    );

    expect(output).toHaveProperty('exam');
    expect(output).toHaveProperty('files');

    expect(output.exam.password).toBe(PASSWORD);
    expect(output.exam.content.title).toBe('Uusi koe');

    expect(output.files['exam.json']).toBeInstanceOf(Buffer);
    expect(output.files['nsa.zip']).toBeInstanceOf(Buffer);
  });
});
