# Unifi FW Image Tool – Chat Transcript Summary (21 mei 2025)

> *Opslag van de essentie van deze chat, zodat onze voortgang en afspraken blijven bewaard.*

## Besproken punten

1. **Port naar TypeScript/Node.js**

   * Bestand: `unifi-fw-tool.ts` (in canvas)
     \* Implementeert: `split`, `build`, `crc` met progress‑bar, CRC‑checks, header/part parsing.
2. **Project­structuur toegevoegd**

   * `package.json` – scripts `build`, `dev`, `start`, dependencies.
   * `tsconfig.json` – ES2020 / strict / dist‑output.
   * `.vscode/launch.json` – debugconfig voor VS Code met ts‑node en gecompileerde variant.
3. **Build‑ & ontwikkelworkflow**

   ```bash
   npm install        # deps
   npm run dev        # live‑reload
   npm run build      # compile naar dist/
   npm start          # draai CLI uit dist/
   ```
4. **Canvas-bestanden**

   | Bestand                      | Omschrijving               |
   | ---------------------------- | -------------------------- |
   | `unifi-fw-tool.ts`           | TypeScript broncode (CLI)  |
   | `package.json`               | NPM metadata + scripts     |
   | `tsconfig.json`              | TypeScript compiler‑config |
   | `.vscode/launch.json`        | VS Code debug‑profielen    |
   | `docs/chatlog-2025-05-21.md` | Deze samenvatting          |

## Hoe verder?

* **Wijzigingen** – Bewerken van een canvasbestand in de sidebar past het project permanent aan.
* **Nieuwe sessie** – Upload dit markdown‑bestand of verwijs ernaar zodat ik (ChatGPT) direct de context terug heb.
* **Versiebeheer** – Overweeg het project in een Git‑repo te zetten (commit canvasbestanden) voor echte history.
