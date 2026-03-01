import { open } from "node:fs/promises"
import { performance } from "node:perf_hooks"

import { AnchorAutomaton } from "./ahoCorasick.js"
import type { CompiledSignature } from "./signature.js"

export interface SignatureMatch {
  readonly signatureId: string
  readonly pattern: string
  readonly offset: number
}

export interface ScanOptions {
  readonly chunkSize?: number
  readonly maxMatches?: number
}

export interface ScanReport {
  readonly filePath: string
  readonly bytesScanned: number
  readonly signaturesScanned: number
  readonly durationMs: number
  readonly truncated: boolean
  readonly matches: ReadonlyArray<SignatureMatch>
}

const DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024

const matchesSignatureAt = (
  data: Uint8Array,
  start: number,
  signature: CompiledSignature
): boolean => {
  for (let index = 0; index < signature.length; index += 1) {
    const dataByte = data[start + index]

    if (dataByte === undefined) {
      return false
    }

    const mask = signature.masks[index]
    const value = signature.values[index]

    if (mask === undefined || value === undefined) {
      return false
    }

    if ((dataByte & mask) !== value) {
      return false
    }
  }

  return true
}

const parsePositiveInt = (value: number, optionName: string): number => {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${optionName} must be a positive integer`)
  }

  return value
}

export const scanFile = async (
  filePath: string,
  signatures: ReadonlyArray<CompiledSignature>,
  options: ScanOptions = {}
): Promise<ScanReport> => {
  if (signatures.length === 0) {
    throw new Error("At least one compiled signature is required")
  }

  const chunkSize = parsePositiveInt(options.chunkSize ?? DEFAULT_CHUNK_SIZE, "chunkSize")
  const maxMatches =
    options.maxMatches === undefined
      ? Number.POSITIVE_INFINITY
      : parsePositiveInt(options.maxMatches, "maxMatches")

  const maxPatternLength = Math.max(...signatures.map((signature) => signature.length))
  const overlap = Math.max(0, maxPatternLength - 1)

  const automaton = AnchorAutomaton.build(signatures)
  const matches: SignatureMatch[] = []
  const startedAt = performance.now()

  const readBuffer = Buffer.allocUnsafe(chunkSize)
  let bytesScanned = 0
  let tail = Buffer.alloc(0)
  let truncated = false

  const fileHandle = await open(filePath, "r")

  try {
    while (!truncated) {
      const { bytesRead } = await fileHandle.read(readBuffer, 0, chunkSize, bytesScanned)

      if (bytesRead === 0) {
        break
      }

      const chunk = readBuffer.subarray(0, bytesRead)
      const combined = tail.length > 0 ? Buffer.concat([tail, chunk]) : chunk

      const chunkStartOffset = bytesScanned - tail.length

      automaton.forEachHit(combined, (signatureIndex, anchorEnd) => {
        if (truncated) {
          return
        }

        const signature = signatures[signatureIndex]

        if (signature === undefined) {
          return
        }

        const anchorLength = signature.anchor.length
        const anchorStart = anchorEnd - anchorLength + 1
        const candidateStart = anchorStart - signature.anchorOffset

        if (candidateStart < 0) {
          return
        }

        const candidateEnd = candidateStart + signature.length

        if (candidateEnd > combined.length) {
          return
        }

        const absoluteOffset = chunkStartOffset + candidateStart
        const earliestNewOffset = bytesScanned - (signature.length - 1)

        if (absoluteOffset < earliestNewOffset) {
          return
        }

        if (!matchesSignatureAt(combined, candidateStart, signature)) {
          return
        }

        matches.push({
          signatureId: signature.id,
          pattern: signature.pattern,
          offset: absoluteOffset
        })

        if (matches.length >= maxMatches) {
          truncated = true
        }
      })

      bytesScanned += bytesRead

      const nextTailLength = Math.min(overlap, combined.length)
      tail = nextTailLength > 0
        ? Buffer.from(combined.subarray(combined.length - nextTailLength))
        : Buffer.alloc(0)
    }
  } finally {
    await fileHandle.close()
  }

  matches.sort((left, right) => {
    if (left.offset !== right.offset) {
      return left.offset - right.offset
    }

    return left.signatureId.localeCompare(right.signatureId)
  })

  return {
    filePath,
    bytesScanned,
    signaturesScanned: signatures.length,
    durationMs: performance.now() - startedAt,
    truncated,
    matches
  }
}
