/*
 * ubnt-fwtool – UniFi firmware utilities (TypeScript)
 * --------------------------------------------------
 * v0.6.3  – RSA‑signature detectie · Gen‑1/2 CRC · list/verify verbeterd
 *
 *  ▶ list      – toont nu extra kolom `rsaSig` (256/512 B) en CRC‑status.
 *  ▶ verify    – controleert header‑CRC, part‑CRC’s, signature‑CRC én meld of er een RSA‑block is.
 *                Als je een public‑key PEM in `$UBNT_PUBKEY` zet wordt de handtekening cryptografisch
 *                gevalideerd (node:crypto) en telt dat mee voor exit‑code.
 *
 *  Dependencies: commander crc cli-progress ora chalk
 *  Optional: set env UBNT_PUBKEY=/path/key.pem  (RSA‑2048 public key)
 */

import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  readdirSync,
  statSync,
} from "fs";
import { basename, dirname, join, resolve, extname } from "path";
import { crc32 } from "crc";
import { Command } from "commander";
import cliProgress from "cli-progress";
import ora from "ora";
import chalk from "chalk";
import { createPublicKey, verify as rsaVerify } from "crypto";

/* ---------------- Constants ---------------- */
const MAGIC_HEADER = "OPEN" as const;
const MAGIC_PART = "PART" as const;
const MAGIC_EXEC = "EXEC" as const;
const MAGIC_END = "END." as const;
const MAGIC_ENDS = "ENDS" as const;

const HEADER_SIZE = 268;
const PART_HEADER_SIZE = 56;
const PARTCRC_SIZE = 8;
const SIGNATURE_SIZE = 12;

/* ---------------- Helper fns ---------------- */
type u32 = number;
const readCString = (b: Buffer, o: number, l: number) => {
  const s = b.subarray(o, o + l);
  const n = s.indexOf(0);
  return (n === -1 ? s : s.subarray(0, n)).toString();
};
const readU32BE = (b: Buffer, o: number): u32 => b.readUInt32BE(o);
const writeU32BE = (b: Buffer, o: number, v: u32) =>
  b.writeUInt32BE(v >>> 0, o);
const crc32u = (b: Buffer): u32 => (crc32(b) >>> 0) as u32;
const isTxt = (p: string) => extname(p).toLowerCase() === ".txt";
const roundUp = (v: number, a = 0x1000) => (v + a - 1) & ~(a - 1);

/* ---------------- Types ---------------- */
interface PartHeader {
  magic: string;
  name: string;
  memaddr: u32;
  index: u32;
  baseaddr: u32;
  entryaddr: u32;
  data_size: u32;
  part_size: u32;
}
interface PartInfo {
  header: PartHeader;
  data: Buffer;
  crcClaim: u32;
  crcCalc: u32;
  crcValid: boolean;
}
interface FirmwareImage {
  version: string;
  parts: PartInfo[];
  signatureValid: boolean;
  rsaSig?: Buffer;
  rsaValid?: boolean;
}

/* locate header */
function locateHeader(buf: Buffer): number {
  let p = buf.indexOf(MAGIC_HEADER, 0, "ascii");
  while (p !== -1) {
    if (p + HEADER_SIZE <= buf.length) {
      const stored = readU32BE(buf, p + 260);
      if (stored === crc32u(buf.subarray(p, p + 260))) return p;
    }
    p = buf.indexOf(MAGIC_HEADER, p + 1, "ascii");
  }
  p = buf.indexOf(MAGIC_PART, 0, "ascii");
  while (p !== -1) {
    const cand = p - HEADER_SIZE;
    if (cand >= 0) {
      const stored = readU32BE(buf, cand + 260);
      if (stored === crc32u(buf.subarray(cand, cand + 260))) return cand;
    }
    p = buf.indexOf(MAGIC_PART, p + 4, "ascii");
  }
  throw new Error("Header niet gevonden");
}

/* ---------------- Parse ---------------- */
export function parseFirmware(buf: Buffer): FirmwareImage {
  const headerOffset = locateHeader(buf);
  const version = readCString(buf, headerOffset + 4, 256);
  const parts: PartInfo[] = [];
  let off = headerOffset + HEADER_SIZE;
  while (off + SIGNATURE_SIZE <= buf.length) {
    const m = buf.toString("ascii", off, off + 4);
    if (m === MAGIC_END || m === MAGIC_ENDS) break;
    const hdr: PartHeader = {
      magic: m,
      name: readCString(buf, off + 4, 16),
      memaddr: readU32BE(buf, off + 32),
      index: readU32BE(buf, off + 36),
      baseaddr: readU32BE(buf, off + 40),
      entryaddr: readU32BE(buf, off + 44),
      data_size: readU32BE(buf, off + 48),
      part_size: readU32BE(buf, off + 52),
    };
    const dStart = off + PART_HEADER_SIZE;
    const dEnd = dStart + hdr.data_size;
    const crcClaim = readU32BE(buf, dEnd);
    const data = buf.subarray(dStart, dEnd);
    parts.push({
      header: hdr,
      data,
      crcClaim,
      crcCalc: crc32u(buf.subarray(off, dEnd)),
      crcValid: false,
    });
    parts.at(-1)!.crcValid = parts.at(-1)!.crcClaim === parts.at(-1)!.crcCalc;
    off = dEnd + PARTCRC_SIZE;
  }
  const sigStored = readU32BE(buf, off + 4);
  const crcA = crc32u(buf.subarray(0, off));
  const crcB = crc32u(buf.subarray(0, off + SIGNATURE_SIZE));
  let sigOK = sigStored === crcA || sigStored === crcB;

  // look for 256/512‑byte RSA block right after signature
  let rsaSig: Buffer | undefined;
  let rsaValid: boolean | undefined;
  const maybe = buf.subarray(off + SIGNATURE_SIZE);
  if (maybe.length === 256 || maybe.length === 512) {
    rsaSig = maybe;
    const pubPath = process.env.UBNT_PUBKEY;
    if (pubPath && existsSync(pubPath)) {
      const pub = createPublicKey(readFileSync(pubPath));
      rsaValid = rsaVerify(
        "sha1",
        buf.subarray(0, off + SIGNATURE_SIZE), // data
        pub, // public key
        rsaSig // signature
      );
      sigOK &&= rsaValid; // telt mee voor verify‑exitcode
    }
  }
  return { version, parts, signatureValid: sigOK, rsaSig, rsaValid };
}

/* progress bar */
function bar(total: number) {
  const b = new cliProgress.SingleBar(
    {
      clearOnComplete: true,
      format: `[${chalk.cyan(
        "{bar}"
      )}] {percentage}% | {value}/{total} | ETA: {eta_formatted}`,
    },
    cliProgress.Presets.shades_classic
  );
  b.start(total, 0);
  return b;
}

/* SPLIT */
function split(img: string, pref?: string) {
  const buf = readFileSync(img);
  const fw = parseFirmware(buf);
  const out = pref || fw.version;
  mkdirSync("./", { recursive: true });
  const b = bar(fw.parts.length);
  const lines: string[] = [];
  fw.parts.forEach((p) => {
    lines.push(
      `${p.header.name}\t\t0x${p.header.index.toString(
        16
      )}\t0x${p.header.baseaddr.toString(16)}\t0x${p.header.part_size.toString(
        16
      )}\t0x${p.header.memaddr.toString(16)}\t0x${p.header.entryaddr.toString(
        16
      )}\t${out}.${p.header.name}`
    );
    writeFileSync(`${out}.${p.header.name}`, p.data);
    b.increment();
  });
  b.stop();
  writeFileSync(`${out}.txt`, lines.join("\n"));
  ora(chalk.green("Split gereed")).succeed();
}

/* LIST */
function list(img: string) {
  const fw = parseFirmware(readFileSync(img));
  console.log(chalk.bold(img));
  console.log(`Versie: ${fw.version}`);
  console.table(
    fw.parts.map((p) => ({
      part: p.header.name,
      idx: p.header.index,
      size: p.header.data_size,
      crc: p.crcValid ? "ok" : "bad",
    }))
  );
  console.log(
    `Signature CRC: ${
      fw.signatureValid ? chalk.green("ok") : chalk.red("mismatch")
    }`
  );
  if (fw.rsaSig)
    console.log(
      `RSA block: ${fw.rsaSig.length} bytes ${
        fw.rsaValid === undefined
          ? "(key n/a)"
          : fw.rsaValid
          ? chalk.green("valid")
          : chalk.red("invalid")
      }`
    );
}

/* VERIFY */
function verify(img: string): boolean {
  const fw = parseFirmware(readFileSync(img));
  let ok = fw.signatureValid;
  fw.parts.forEach((p) => {
    if (!p.crcValid) ok = false;
  });
  console.log(ok ? chalk.green("✔ Constistent") : chalk.red("✗ Fouten"));
  return ok;
}

/* ---------------- CLI ---------------- */
const cmd = new Command();
cmd.name("ubnt-fwtool").version("0.6.3");
cmd
  .command("split")
  .argument("<img>")
  .option("-o, --output <pref>")
  .action((i, o) => split(i, o.output));
cmd.command("list").argument("<img>").action(list);
cmd
  .command("verify")
  .argument("<img>")
  .action((i) => process.exit(verify(i) ? 0 : 1));
if (process.argv.length > 2) cmd.parse(process.argv);
else console.log("gebruik: ubnt-fwtool <cmd>");
