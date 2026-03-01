export interface SignatureDefinition {
  readonly id: string
  readonly pattern: string
}

export interface CompiledSignature {
  readonly id: string
  readonly pattern: string
  readonly values: Uint8Array
  readonly masks: Uint8Array
  readonly length: number
  readonly anchorOffset: number
  readonly anchor: Uint8Array
}

interface ParsedByte {
  readonly value: number
  readonly mask: number
}

const NAMED_SIGNATURE_PATTERN = /^([A-Za-z0-9_.-]+)\s*[:=]\s*(.+)$/

const HEX_NIBBLE_PATTERN = /^[0-9A-Fa-f]$/

const parseNibble = (char: string): ParsedByte => {
  if (char === "?") {
    return { value: 0x0, mask: 0x0 }
  }

  if (!HEX_NIBBLE_PATTERN.test(char)) {
    throw new Error(`Invalid HEX nibble: ${char}`)
  }

  return { value: Number.parseInt(char, 16), mask: 0xf }
}

const parseByteToken = (token: string): ParsedByte => {
  if (token.length !== 2) {
    throw new Error(`Invalid token \"${token}\": expected exactly 2 characters`)
  }

  const high = parseNibble(token[0] ?? "")
  const low = parseNibble(token[1] ?? "")

  return {
    value: (high.value << 4) | low.value,
    mask: (high.mask << 4) | low.mask
  }
}

const splitTokenToByteTokens = (token: string): ReadonlyArray<string> => {
  if (token.length % 2 !== 0) {
    throw new Error(`Invalid token \"${token}\": expected an even number of HEX characters`)
  }

  const byteTokens: string[] = []

  for (let index = 0; index < token.length; index += 2) {
    byteTokens.push(token.slice(index, index + 2))
  }

  return byteTokens
}

const tokenizePattern = (pattern: string): ReadonlyArray<string> => {
  const sourceTokens = pattern.trim().split(/\s+/).filter((token) => token.length > 0)

  if (sourceTokens.length === 0) {
    throw new Error("Signature pattern is empty")
  }

  return sourceTokens.flatMap((token) => splitTokenToByteTokens(token))
}

const findBestAnchor = (masks: Uint8Array): { readonly start: number; readonly length: number } => {
  let bestStart = -1
  let bestLength = 0

  let runStart = 0
  let runLength = 0

  for (let index = 0; index < masks.length; index += 1) {
    if (masks[index] === 0xff) {
      if (runLength === 0) {
        runStart = index
      }

      runLength += 1

      if (runLength > bestLength) {
        bestLength = runLength
        bestStart = runStart
      }
      continue
    }

    runLength = 0
  }

  if (bestLength === 0 || bestStart < 0) {
    throw new Error("Signature must contain at least one concrete byte")
  }

  return { start: bestStart, length: bestLength }
}

export const compileSignature = (definition: SignatureDefinition): CompiledSignature => {
  const tokens = tokenizePattern(definition.pattern)

  const parsedBytes = tokens.map((token) => parseByteToken(token))
  const values = Uint8Array.from(parsedBytes.map((item) => item.value))
  const masks = Uint8Array.from(parsedBytes.map((item) => item.mask))

  const anchor = findBestAnchor(masks)

  return {
    id: definition.id,
    pattern: definition.pattern,
    values,
    masks,
    length: values.length,
    anchorOffset: anchor.start,
    anchor: values.slice(anchor.start, anchor.start + anchor.length)
  }
}

export const compileSignatures = (
  definitions: ReadonlyArray<SignatureDefinition>
): ReadonlyArray<CompiledSignature> => {
  if (definitions.length === 0) {
    throw new Error("At least one signature is required")
  }

  return definitions.map((definition) => compileSignature(definition))
}

export const parseInlineSignature = (rawValue: string, ordinal: number): SignatureDefinition => {
  const trimmed = rawValue.trim()

  if (trimmed.length === 0) {
    throw new Error("Inline signature value is empty")
  }

  const namedMatch = NAMED_SIGNATURE_PATTERN.exec(trimmed)

  if (namedMatch !== null) {
    const id = namedMatch[1]
    const pattern = namedMatch[2]

    if (id === undefined || pattern === undefined) {
      throw new Error("Named signature groups are missing")
    }

    return { id, pattern: pattern.trim() }
  }

  return {
    id: `signature-${ordinal}`,
    pattern: trimmed
  }
}

export const parseSignatureList = (
  content: string,
  unnamedPrefix = "signature"
): ReadonlyArray<SignatureDefinition> => {
  const definitions: SignatureDefinition[] = []
  let unnamedCount = 0

  for (const sourceLine of content.split(/\r?\n/u)) {
    const line = sourceLine.trim()

    if (line.length === 0 || line.startsWith("#") || line.startsWith("//")) {
      continue
    }

    const namedMatch = NAMED_SIGNATURE_PATTERN.exec(line)

    if (namedMatch !== null) {
      const id = namedMatch[1]
      const pattern = namedMatch[2]

      if (id === undefined || pattern === undefined) {
        throw new Error("Named signature groups are missing")
      }

      definitions.push({ id, pattern: pattern.trim() })
      continue
    }

    unnamedCount += 1
    definitions.push({
      id: `${unnamedPrefix}-${unnamedCount}`,
      pattern: line
    })
  }

  return definitions
}
