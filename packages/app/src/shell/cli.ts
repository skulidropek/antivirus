import { readFile } from "node:fs/promises"

import { Effect } from "effect"

import {
  parseInlineSignature,
  parseSignatureList,
  type SignatureDefinition
} from "../core/signature.js"

const DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024

export interface ScanCommand {
  readonly kind: "scan"
  readonly filePath: string
  readonly signatures: ReadonlyArray<SignatureDefinition>
  readonly chunkSize: number
  readonly maxMatches?: number
  readonly json: boolean
}

export interface HelpCommand {
  readonly kind: "help"
  readonly message: string
}

export type CliCommand = ScanCommand | HelpCommand

const HELP_TEXT = [
  "Usage:",
  "  pnpm start -- scan --file <path> (--signature <hex> | --signatures-file <path>) [options]",
  "",
  "Options:",
  "  -f, --file <path>               Path to file for scanning",
  "  -s, --signature <pattern>       Signature in HEX format, supports wildcards with ? (e.g. DE AD ?? BE EF)",
  "                                  Optional named form: <id>:<pattern>",
  "  -S, --signatures-file <path>    File with signatures, one per line",
  "  -c, --chunk-size <bytes>        Read chunk size in bytes (default: 8388608)",
  "  -m, --max-matches <count>       Stop after this number of matches",
  "      --json                      Output report as JSON",
  "  -h, --help                      Show help"
].join("\n")

const ensurePositiveInt = (rawValue: string, optionName: string): number => {
  const parsedValue = Number.parseInt(rawValue, 10)

  if (!Number.isInteger(parsedValue) || parsedValue <= 0) {
    throw new Error(`${optionName} must be a positive integer`)
  }

  return parsedValue
}

const readOptionValue = (args: ReadonlyArray<string>, index: number, optionName: string): string => {
  const value = args[index + 1]

  if (value === undefined) {
    throw new Error(`Missing value for ${optionName}`)
  }

  return value
}

const parseCli = async (argv: ReadonlyArray<string>): Promise<CliCommand> => {
  if (argv.includes("--help") || argv.includes("-h") || argv[0] === "help") {
    return { kind: "help", message: HELP_TEXT }
  }

  let cursor = 0

  if (argv[0] === "scan") {
    cursor = 1
  }

  let filePath: string | undefined
  let chunkSize = DEFAULT_CHUNK_SIZE
  let maxMatches: number | undefined
  let signaturesFilePath: string | undefined
  const inlineSignatures: SignatureDefinition[] = []
  let json = false

  while (cursor < argv.length) {
    const arg = argv[cursor]

    if (arg === undefined) {
      cursor += 1
      continue
    }

    switch (arg) {
      case "--file":
      case "-f": {
        filePath = readOptionValue(argv, cursor, arg)
        cursor += 2
        break
      }

      case "--signature":
      case "-s": {
        const rawSignature = readOptionValue(argv, cursor, arg)
        inlineSignatures.push(parseInlineSignature(rawSignature, inlineSignatures.length + 1))
        cursor += 2
        break
      }

      case "--signatures-file":
      case "-S": {
        signaturesFilePath = readOptionValue(argv, cursor, arg)
        cursor += 2
        break
      }

      case "--chunk-size":
      case "-c": {
        const rawChunkSize = readOptionValue(argv, cursor, arg)
        chunkSize = ensurePositiveInt(rawChunkSize, "chunk-size")
        cursor += 2
        break
      }

      case "--max-matches":
      case "-m": {
        const rawMaxMatches = readOptionValue(argv, cursor, arg)
        maxMatches = ensurePositiveInt(rawMaxMatches, "max-matches")
        cursor += 2
        break
      }

      case "--json": {
        json = true
        cursor += 1
        break
      }

      default: {
        throw new Error(`Unknown argument: ${arg}`)
      }
    }
  }

  if (filePath === undefined) {
    throw new Error("Missing required option: --file")
  }

  const fileSignatures = signaturesFilePath === undefined
    ? []
    : parseSignatureList(await readFile(signaturesFilePath, "utf8"), "file-signature")

  const signatures = [...inlineSignatures, ...fileSignatures]

  if (signatures.length === 0) {
    throw new Error("At least one signature must be provided")
  }

  const scanCommandBase = {
    kind: "scan",
    filePath,
    signatures,
    chunkSize,
    json
  } as const satisfies Omit<ScanCommand, "maxMatches">

  return maxMatches === undefined
    ? scanCommandBase
    : { ...scanCommandBase, maxMatches }
}

const toError = (error: unknown): Error =>
  error instanceof Error ? error : new Error(String(error))

export const readCliCommand = Effect.tryPromise({
  try: () => parseCli(process.argv.slice(2)),
  catch: toError
})

export const helpText = HELP_TEXT
