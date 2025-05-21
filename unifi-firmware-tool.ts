/*
 * ubnt-fwtool – UniFi firmware utilities (TypeScript)
 * --------------------------------------------------
 * v0.4.0 – **stabilised build**
 *
 *  – Consolidated header handling (detects internal "OPEN" header anywhere in file, incl. UBNT wrappers).
 *  – Removed duplicate constants and stray tokens.
 *  – Type‑safe returns; no more implicit `void`.
 *  – Clean compile under TS 5.x.
 *
 *  Dependencies (add ‑D for dev):  commander crc cli-progress inquirer ora
 *   npm i commander crc cli-progress inquirer ora
 *   npm i -D typescript ts-node @types/node @types/inquirer
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

/* -------------------------------------------------------------------------
 * Constants / sizes
 * ---------------------------------------------------------------------- */

const MAGIC_HEADER = "OPEN" as const; // internal standard header we parse
const MAGIC_HEADER_WRITE = "OPEN" as const; // what we emit when building
const MAGIC_PART = "PART" as const;
const MAGIC_EXEC = "EXEC" as const;
const MAGIC_END = "END." as const;
const MAGIC_ENDS = "ENDS" as const;
const MAGIC_LEN = 4;

const HEADER_SIZE = 4 + 256 + 4 + 4; // 268
const PART_HEADER_SIZE = 4 + 16 + 12 + 4 * 6; // 56
const PARTCRC_SIZE = 8; // crc + pad
const SIGNATURE_SIZE = 12; // 4 magic + 4 crc + 4 pad

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

type u32 = number;

const readCString = (b: Buffer, o: number, l: number): string => {
  const slice = b.subarray(o, o + l);
  const nul = slice.indexOf(0);
  return (nul === -1 ? slice : slice.subarray(0, nul)).toString();
};
const readU32BE = (b: Buffer, o: number): u32 => b.readUInt32BE(o);
const writeU32BE = (b: Buffer, o: number, v: u32) =>
  b.writeUInt32BE(v >>> 0, o);
const crc32u = (b: Buffer): u32 => (crc32(b) >>> 0) as u32;
const isTxt = (p: string) => extname(p).toLowerCase() === ".txt";
const roundUp = (v: number, a = 0x1000) => (v + a - 1) & ~(a - 1);

/* -------------------------------------------------------------------------
 * Type definitions
 * ---------------------------------------------------------------------- */

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
}

/* -------------------------------------------------------------------------
 * Search for the first well‑formed OPEN header anywhere in the buffer.
 * Returns offset or throws.
 * ---------------------------------------------------------------------- */
function locateHeader(buf: Buffer): number {
  // 1. direct search for "OPEN" header with CRC check
  let pos = buf.indexOf(MAGIC_HEADER, 0, "ascii");
  while (pos !== -1) {
    if (pos + HEADER_SIZE <= buf.length) {
      const crcStored = readU32BE(buf, pos + 260);
      const crcCalc = crc32u(buf.subarray(pos, pos + 260));
      if (crcStored === crcCalc) return pos;
    }
    pos = buf.indexOf(MAGIC_HEADER, pos + 1, "ascii");
  }
  // 2. fallback: look for first "PART" magic, assume header_size bytes before
  let partPos = buf.indexOf(MAGIC_PART, 0, "ascii");
  while (partPos !== -1) {
    const cand = partPos - HEADER_SIZE;
    if (cand >= 0) {
      const crcStored = readU32BE(buf, cand + 260);
      const crcCalc = crc32u(buf.subarray(cand, cand + 260));
      if (crcStored === crcCalc) return cand;
    }
    partPos = buf.indexOf(MAGIC_PART, partPos + 4, "ascii");
  }
  throw new Error(
    "No valid firmware header found (tried OPEN & PART heuristics)"
  );
}

/* -------------------------------------------------------------------------
 * Parser
 * ---------------------------------------------------------------------- */
export function parseFirmware(buf: Buffer, debug = false): FirmwareImage {
  const headerOffset = locateHeader(buf);
  if (debug) console.log(`Header found @ 0x${headerOffset.toString(16)}`);

  const version = readCString(buf, headerOffset + 4, 256);
  const hdrCrcStored = readU32BE(buf, headerOffset + 260);
  const hdrCrcCalc = crc32u(buf.subarray(headerOffset, headerOffset + 260));
  if (debug && hdrCrcStored !== hdrCrcCalc) console.warn("Header CRC mismatch");

  const parts: PartInfo[] = [];
  let off = headerOffset + HEADER_SIZE;
  while (off + SIGNATURE_SIZE <= buf.length) {
    const magic = buf.toString("ascii", off, off + 4);
    if (magic === MAGIC_END || magic === MAGIC_ENDS) break; // reached signature
    if (magic !== MAGIC_PART && magic !== MAGIC_EXEC) {
      if (debug)
        console.warn(`Unknown part magic '${magic}' @ 0x${off.toString(16)}`);
      throw new Error(`Unknown part magic '${magic}'`);
    }

    const name = readCString(buf, off + 4, 16);
    const memaddr = readU32BE(buf, off + 32);
    const index = readU32BE(buf, off + 36);
    const baseaddr = readU32BE(buf, off + 40);
    const entryaddr = readU32BE(buf, off + 44);
    const data_size = readU32BE(buf, off + 48);
    const part_size = readU32BE(buf, off + 52);

    const dataStart = off + PART_HEADER_SIZE;
    const dataEnd = dataStart + data_size;
    const crcClaim = readU32BE(buf, dataEnd);
    const data = buf.subarray(dataStart, dataEnd);
    const crcCalc = crc32u(buf.subarray(off, dataEnd));

    parts.push({
      header: {
        magic,
        name,
        memaddr,
        index,
        baseaddr,
        entryaddr,
        data_size,
        part_size,
      },
      data,
      crcClaim,
      crcCalc,
      crcValid: crcClaim === crcCalc,
    });

    off = dataEnd + PARTCRC_SIZE;
  }

  const sigMagic = buf.toString("ascii", off, off + 4);
  if (sigMagic !== MAGIC_END && sigMagic !== MAGIC_ENDS)
    throw new Error("Bad signature magic");
  const sigCrcStored = readU32BE(buf, off + 4);
  const sigCrcCalc = crc32u(buf.subarray(0, off));

  return { version, parts, signatureValid: sigCrcStored === sigCrcCalc };
}

/* -------------------------------------------------------------------------
 * Split (extract)
 * ---------------------------------------------------------------------- */
export function splitFirmware(imgPath: string, prefix?: string, debug = false) {
  if (!existsSync(imgPath)) throw new Error(`File not found: ${imgPath}`);
  const spin = ora("Lezen firmware…").start();
  const buf = readFileSync(imgPath);
  spin.succeed("Firmware geladen");

  const fw = parseFirmware(buf, debug);
  const outPrefix = prefix || fw.version || basename(imgPath);
  const bar = new cliProgress.SingleBar(
    { clearOnComplete: true },
    cliProgress.Presets.shades_classic
  );

  mkdirSync("./", { recursive: true });
  const descriptor: string[] = [];
  bar.start(fw.parts.length, 0);

  fw.parts.forEach((p) => {
    const idxHex = `0x${p.header.index.toString(16).padStart(2, "0")}`;
    descriptor.push(
      `${p.header.name}\t\t${idxHex}\t0x${p.header.baseaddr
        .toString(16)
        .padStart(8, "0")}\t0x${p.header.part_size
        .toString(16)
        .padStart(8, "0")}\t0x${p.header.memaddr
        .toString(16)
        .padStart(8, "0")}\t0x${p.header.entryaddr
        .toString(16)
        .padStart(8, "0")}\t${outPrefix}.${p.header.name}`
    );
    writeFileSync(`${outPrefix}.${p.header.name}`, p.data);
    bar.increment();
  });
  bar.stop();
  writeFileSync(`${outPrefix}.txt`, descriptor.join("\n"));
  ora({
    text: `Split OK – ${fw.parts.length} parts`,
    color: "green",
  }).succeed();
}

/* -------------------------------------------------------------------------
 * Layout parsing (txt or autodetect)
 * ---------------------------------------------------------------------- */
interface LayoutPart {
  name: string;
  index: u32;
  baseaddr: u32;
  part_size: u32;
  memaddr: u32;
  entryaddr: u32;
  filename: string;
  data: Buffer;
  magic: string;
}

const parseHex = (s: string): u32 => parseInt(s.replace(/^0x/i, ""), 16);

function autoLayout(prefix: string, debug = false): LayoutPart[] {
  const dir =
    existsSync(prefix) && statSync(prefix).isDirectory()
      ? prefix
      : dirname(resolve(prefix));
  const base = basename(prefix);
  const files = readdirSync(dir).filter(
    (f) => f.startsWith(base) && !f.endsWith(".txt") && !f.endsWith(".bin")
  );
  if (!files.length) throw new Error("No blobs found for auto layout");
  return files.map((f, idx) => {
    const data = readFileSync(join(dir, f));
    return {
      name: f.replace(/^.*?\./, ""),
      index: idx,
      baseaddr: 0,
      part_size: roundUp(data.length),
      memaddr: 0,
      entryaddr: 0,
      filename: join(dir, f),
      data,
      magic: MAGIC_PART,
    } as LayoutPart;
  });
}

function parseLayout(fileOrPrefix: string, debug = false): LayoutPart[] {
  if (!isTxt(fileOrPrefix)) return autoLayout(fileOrPrefix, debug);
  const dir = dirname(resolve(fileOrPrefix));
  const txt = readFileSync(fileOrPrefix, "utf-8");
  const parts: LayoutPart[] = [];
  txt.split(/\r?\n/).forEach((line) => {
    const l = line.trim();
    if (!l || l.startsWith("#")) return;
    const c = l.split(/\t+/);
    if (c.length < 7) return;
    const [name, idxHex, baseHex, sizeHex, memHex, entryHex, fileName] = c;
    const data = readFileSync(join(dir, fileName));
    parts.push({
      name,
      index: parseHex(idxHex),
      baseaddr: parseHex(baseHex),
      part_size: parseHex(sizeHex),
      memaddr: parseHex(memHex),
      entryaddr: parseHex(entryHex),
      filename: join(dir, fileName),
      data,
      magic: name === "script" ? MAGIC_EXEC : MAGIC_PART,
    });
  });
  return parts;
}

/* -------------------------------------------------------------------------
 * Build
 * ---------------------------------------------------------------------- */
export function buildFirmware(
  layoutOrPrefix: string,
  out = "firmware.bin",
  version = "UNKNOWN",
  debug = false
) {
  const parts = parseLayout(layoutOrPrefix, debug);
  let total = HEADER_SIZE + SIGNATURE_SIZE;
  parts.forEach(
    (p) => (total += PART_HEADER_SIZE + p.data.length + PARTCRC_SIZE)
  );

  const buf = Buffer.alloc(total, 0);
  buf.write(MAGIC_HEADER_WRITE, 0, MAGIC_LEN, "ascii");
  buf.write(version, 4, Math.min(255, version.length), "ascii");
  writeU32BE(buf, 260, crc32u(buf.subarray(0, 260)));

  const bar = new cliProgress.SingleBar(
    { clearOnComplete: true },
    cliProgress.Presets.shades_classic
  );
  bar.start(parts.length, 0);

  let off = HEADER_SIZE;
  parts.forEach((p) => {
    buf.write(p.magic, off, MAGIC_LEN, "ascii");
    buf.write(p.name, off + 4, Math.min(15, p.name.length), "ascii");
    writeU32BE(buf, off + 32, p.memaddr);
    writeU32BE(buf, off + 36, p.index);
    writeU32BE(buf, off + 40, p.baseaddr);
    writeU32BE(buf, off + 44, p.entryaddr);
    writeU32BE(buf, off + 48, p.data.length);
    writeU32BE(buf, off + 52, p.part_size);
    p.data.copy(buf, off + PART_HEADER_SIZE);
    writeU32BE(
      buf,
      off + PART_HEADER_SIZE + p.data.length,
      crc32u(buf.subarray(off, off + PART_HEADER_SIZE + p.data.length))
    );
    off += PART_HEADER_SIZE + p.data.length + PARTCRC_SIZE;
    bar.increment();
  });
  bar.stop();

  buf.write(MAGIC_END, off, MAGIC_LEN, "ascii");
  writeU32BE(buf, off + 4, crc32u(buf.subarray(0, off)));

  writeFileSync(out, buf);
  ora({ text: `Firmware built → ${out}`, color: "green" }).succeed();
}

/* -------------------------------------------------------------------------
 * Interactive wizard
 * ---------------------------------------------------------------------- */
async function wizard() {
  const inquirer: any = (await import("inquirer")).default;

  const { act } = await inquirer.prompt({
    type: "list",
    name: "act",
    message: "Wat wil je doen?",
    choices: [
      { name: "Split bestaande firmware", value: "split" },
      { name: "Build nieuwe firmware", value: "build" },
    ],
  });

  if (act === "split") {
    const { file, prefix } = await inquirer.prompt([
      {
        type: "input",
        name: "file",
        message: "Pad naar firmware.bin",
        validate: (p: string) => existsSync(p) || "Bestand bestaat niet",
      },
      {
        type: "input",
        name: "prefix",
        message: "Output-prefix (enter voor auto)",
      },
    ]);
    splitFirmware(file, prefix || undefined, true);
  } else {
    const { layout, output, ver } = await inquirer.prompt([
      {
        type: "input",
        name: "layout",
        message: "Descriptor .txt of prefix",
        validate: (p: string) => existsSync(p) || "Bestand bestaat niet",
      },
      {
        type: "input",
        name: "output",
        message: "Uitvoer-bestand",
        default: "firmware.bin",
      },
      { type: "input", name: "ver", message: "FW-versie", default: "UNKNOWN" },
    ]);
    buildFirmware(layout, output, ver, true);
  }
}

/* -------------------------------------------------------------------------
 * CLI wiring
 * ---------------------------------------------------------------------- */
const prog = new Command();
prog.name("ubnt-fwtool").version("0.4.0");
prog
  .command("split")
  .argument("<image>")
  .option("-o, --output <prefix>")
  .option("-d, --debug")
  .action((img, opts) => splitFirmware(img, opts.output, !!opts.debug));
prog
  .command("build")
  .argument("<layout|prefix>")
  .option("-o, --output <file>")
  .option("-v, --version <str>")
  .option("-d, --debug")
  .action((lay, opts) =>
    buildFirmware(lay, opts.output, opts.version, !!opts.debug)
  );
prog.command("wizard").action(wizard);

if (process.argv.length <= 2) wizard().catch((e) => console.error(e));
else prog.parse(process.argv);
