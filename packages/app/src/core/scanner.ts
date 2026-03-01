import { open } from "node:fs/promises"
import { performance } from "node:perf_hooks"

import type { CompiledSignature } from "./signature.js"

export interface SignatureMatch {
  readonly signatureId: string
  readonly pattern: string
  readonly matchedHex: string
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
const IN_MEMORY_SCAN_LIMIT_BYTES = 2 * 1024 * 1024 * 1024

interface AnchorBuckets {
  readonly hasOneByteAnchors: boolean
  readonly byOne: ReadonlyArray<ReadonlyArray<CompiledSignature> | undefined>
  readonly byTwo: ReadonlyArray<ReadonlyArray<CompiledSignature> | undefined>
}

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

const canUseIndexedAnchorScan = (signatures: ReadonlyArray<CompiledSignature>): boolean =>
  signatures.length <= 32 && signatures.every((signature) => signature.anchor.length >= 2)

const toHexByte = (value: number): string => value.toString(16).padStart(2, "0")

const formatMatchedHex = (data: Uint8Array, start: number, length: number): string => {
  const words: string[] = []

  for (let index = 0; index < length; index += 2) {
    const firstByte = data[start + index]

    if (firstByte === undefined) {
      break
    }

    if (index + 1 >= length) {
      words.push(toHexByte(firstByte))
      break
    }

    const secondByte = data[start + index + 1]

    if (secondByte === undefined) {
      words.push(toHexByte(firstByte))
      break
    }

    words.push(`${toHexByte(firstByte)}${toHexByte(secondByte)}`)
  }

  return words.join(" ")
}

const buildAnchorBuckets = (signatures: ReadonlyArray<CompiledSignature>): AnchorBuckets => {
  const byOne: Array<Array<CompiledSignature> | undefined> = new Array(256)
  const byTwo: Array<Array<CompiledSignature> | undefined> = new Array(65_536)
  let hasOneByteAnchors = false

  for (const signature of signatures) {
    const firstByte = signature.anchor[0]

    if (firstByte === undefined) {
      continue
    }

    if (signature.anchor.length === 1) {
      hasOneByteAnchors = true
      const bucket = byOne[firstByte] ?? []
      bucket.push(signature)
      byOne[firstByte] = bucket
      continue
    }

    const secondByte = signature.anchor[1]

    if (secondByte === undefined) {
      continue
    }

    const key = (firstByte << 8) | secondByte
    const bucket = byTwo[key] ?? []
    bucket.push(signature)
    byTwo[key] = bucket
  }

  return { hasOneByteAnchors, byOne, byTwo }
}

const findMatchesByAnchorIndexOf = (
  data: Buffer,
  signatures: ReadonlyArray<CompiledSignature>,
  chunkStartOffset: number,
  bytesScannedBeforeChunk: number,
  matches: Array<SignatureMatch>,
  maxMatches: number
): boolean => {
  for (const signature of signatures) {
    let searchFrom = 0

    while (searchFrom < data.length) {
      const anchorStart = data.indexOf(signature.anchor, searchFrom)

      if (anchorStart < 0) {
        break
      }

      searchFrom = anchorStart + 1

      const candidateStart = anchorStart - signature.anchorOffset

      if (candidateStart < 0) {
        continue
      }

      const candidateEnd = candidateStart + signature.length

      if (candidateEnd > data.length) {
        continue
      }

      const absoluteOffset = chunkStartOffset + candidateStart
      const earliestNewOffset = bytesScannedBeforeChunk - (signature.length - 1)

      if (absoluteOffset < earliestNewOffset) {
        continue
      }

      if (!matchesSignatureAt(data, candidateStart, signature)) {
        continue
      }

      matches.push({
        signatureId: signature.id,
        pattern: signature.pattern,
        matchedHex: formatMatchedHex(data, candidateStart, signature.length),
        offset: absoluteOffset
      })

      if (matches.length >= maxMatches) {
        return true
      }
    }
  }

  return false
}

const processCandidates = (
  data: Uint8Array,
  anchorStart: number,
  candidates: ReadonlyArray<CompiledSignature> | undefined,
  chunkStartOffset: number,
  bytesScannedBeforeChunk: number,
  matches: Array<SignatureMatch>,
  maxMatches: number
): boolean => {
  if (candidates === undefined) {
    return false
  }

  for (const signature of candidates) {
    const anchorLength = signature.anchor.length
    let anchorMatched = true

    for (let index = 2; index < anchorLength; index += 1) {
      const expected = signature.anchor[index]
      const actual = data[anchorStart + index]

      if (expected === undefined || actual !== expected) {
        anchorMatched = false
        break
      }
    }

    if (!anchorMatched) {
      continue
    }

    const candidateStart = anchorStart - signature.anchorOffset

    if (candidateStart < 0) {
      continue
    }

    const candidateEnd = candidateStart + signature.length

    if (candidateEnd > data.length) {
      continue
    }

    const absoluteOffset = chunkStartOffset + candidateStart
    const earliestNewOffset = bytesScannedBeforeChunk - (signature.length - 1)

    if (absoluteOffset < earliestNewOffset) {
      continue
    }

    if (!matchesSignatureAt(data, candidateStart, signature)) {
      continue
    }

    matches.push({
      signatureId: signature.id,
      pattern: signature.pattern,
      matchedHex: formatMatchedHex(data, candidateStart, signature.length),
      offset: absoluteOffset
    })

    if (matches.length >= maxMatches) {
      return true
    }
  }

  return false
}

const findMatchesInWindow = (
  data: Uint8Array,
  buckets: AnchorBuckets,
  chunkStartOffset: number,
  bytesScannedBeforeChunk: number,
  matches: Array<SignatureMatch>,
  maxMatches: number
): boolean => {
  const lastIndex = data.length - 1

  if (!buckets.hasOneByteAnchors) {
    for (let anchorStart = 0; anchorStart < lastIndex; anchorStart += 1) {
      const firstByte = data[anchorStart]
      const secondByte = data[anchorStart + 1]

      if (firstByte === undefined || secondByte === undefined) {
        continue
      }

      const key = (firstByte << 8) | secondByte
      const twoByteCandidates = buckets.byTwo[key]

      if (twoByteCandidates === undefined) {
        continue
      }

      if (
        processCandidates(
          data,
          anchorStart,
          twoByteCandidates,
          chunkStartOffset,
          bytesScannedBeforeChunk,
          matches,
          maxMatches
        )
      ) {
        return true
      }
    }

    return false
  }

  for (let anchorStart = 0; anchorStart <= lastIndex; anchorStart += 1) {
    const firstByte = data[anchorStart]

    if (firstByte === undefined) {
      continue
    }

    if (anchorStart < lastIndex) {
      const secondByte = data[anchorStart + 1]

      if (secondByte !== undefined) {
        const key = (firstByte << 8) | secondByte
        const twoByteCandidates = buckets.byTwo[key]

        if (twoByteCandidates !== undefined) {
          if (
            processCandidates(
              data,
              anchorStart,
              twoByteCandidates,
              chunkStartOffset,
              bytesScannedBeforeChunk,
              matches,
              maxMatches
            )
          ) {
            return true
          }
        }
      }
    }

    const oneByteCandidates = buckets.byOne[firstByte]

    if (oneByteCandidates !== undefined) {
      if (
        processCandidates(
          data,
          anchorStart,
          oneByteCandidates,
          chunkStartOffset,
          bytesScannedBeforeChunk,
          matches,
          maxMatches
        )
      ) {
        return true
      }
    }
  }

  return false
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

  const buckets = buildAnchorBuckets(signatures)

  const matches: SignatureMatch[] = []
  const startedAt = performance.now()

  let bytesScanned = 0
  let truncated = false

  const fileHandle = await open(filePath, "r")

  try {
    const fileStats = await fileHandle.stat()

    if (fileStats.size <= IN_MEMORY_SCAN_LIMIT_BYTES) {
      const data = await fileHandle.readFile()

      bytesScanned = data.length
      truncated = canUseIndexedAnchorScan(signatures)
        ? findMatchesByAnchorIndexOf(data, signatures, 0, 0, matches, maxMatches)
        : findMatchesInWindow(data, buckets, 0, 0, matches, maxMatches)
    } else {
      const readBuffer = Buffer.allocUnsafe(chunkSize)
      let tail = Buffer.alloc(0)

      while (!truncated) {
        const { bytesRead } = await fileHandle.read(readBuffer, 0, chunkSize, bytesScanned)

        if (bytesRead === 0) {
          break
        }

        const chunk = readBuffer.subarray(0, bytesRead)
        const combined = tail.length > 0 ? Buffer.concat([tail, chunk]) : chunk

        const chunkStartOffset = bytesScanned - tail.length

        truncated = findMatchesInWindow(
          combined,
          buckets,
          chunkStartOffset,
          bytesScanned,
          matches,
          maxMatches
        )

        bytesScanned += bytesRead

        const nextTailLength = Math.min(overlap, combined.length)
        tail =
          nextTailLength > 0
            ? Buffer.from(combined.subarray(combined.length - nextTailLength))
            : Buffer.alloc(0)
      }
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
