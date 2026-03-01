import { describe, expect, it } from "@effect/vitest"
import { Effect } from "effect"

import { scanFile } from "../../src/core/scanner.js"
import { compileSignatures, type SignatureDefinition } from "../../src/core/signature.js"
import { withTempBinaryFile } from "../helpers/temp-binary-file.js"

const readScanReport = (
  bytes: ReadonlyArray<number>,
  definitions: ReadonlyArray<SignatureDefinition>,
  options: Parameters<typeof scanFile>[2]
) =>
  Effect.scoped(
    Effect.gen(function*(_) {
      const { filePath } = yield* _(
        withTempBinaryFile("antivirus-scan-test-", "sample.bin", bytes)
      )

      const signatures = compileSignatures(definitions)

      return yield* _(
        Effect.tryPromise({
          try: () => scanFile(filePath, signatures, options),
          catch: (error) => error instanceof Error ? error : new Error(String(error))
        })
      )
    })
  )

describe("scanFile", () => {
  it.effect("finds signatures that cross chunk boundaries", () =>
    Effect.gen(function*(_) {
      const report = yield* _(
        readScanReport(
          [0x10, 0xAA, 0xBB, 0xCC, 0xDD, 0x99],
          [{ id: "cross-boundary", pattern: "AA BB CC DD" }],
          { chunkSize: 3 }
        )
      )

      yield* _(
        Effect.sync(() => {
          expect(report.matches).toEqual([
            {
              signatureId: "cross-boundary",
              pattern: "AA BB CC DD",
              matchedHex: "aabb ccdd",
              offset: 1
            }
          ])
        })
      )
    }))

  it.effect("handles multiple signatures and wildcard bytes", () =>
    Effect.gen(function*(_) {
      const report = yield* _(
        readScanReport(
          [
            0xDE,
            0xAD,
            0x11,
            0xBE,
            0xEF,
            0x90,
            0xDE,
            0xAD,
            0x22,
            0xBE,
            0xEF
          ],
          [
            { id: "wildcard", pattern: "DE AD ?? BE EF" },
            { id: "exact", pattern: "90 DE AD" }
          ],
          { chunkSize: 4 }
        )
      )

      yield* _(
        Effect.sync(() => {
          expect(report.matches).toEqual([
            {
              signatureId: "wildcard",
              pattern: "DE AD ?? BE EF",
              matchedHex: "dead 11be ef",
              offset: 0
            },
            {
              signatureId: "exact",
              pattern: "90 DE AD",
              matchedHex: "90de ad",
              offset: 5
            },
            {
              signatureId: "wildcard",
              pattern: "DE AD ?? BE EF",
              matchedHex: "dead 22be ef",
              offset: 6
            }
          ])

          expect(report.truncated).toBe(false)
        })
      )
    }))

  it.effect("matches grouped signature with ???? as any two bytes", () =>
    Effect.gen(function*(_) {
      const report = yield* _(
        readScanReport(
          [
            0x00,
            0x08,
            0xF8,
            0x12,
            0x34,
            0xD7,
            0x44,
            0x56,
            0xCC,
            0x09,
            0x96,
            0xA8,
            0xFC,
            0x8F,
            0xEE,
            0xA6,
            0xAF,
            0x99,
            0x08,
            0xF8,
            0xAB,
            0xCD,
            0xD7,
            0x44,
            0x56,
            0xCC,
            0x09,
            0x96,
            0xA8,
            0xFC,
            0x8F,
            0xEE,
            0xA6,
            0xAF
          ],
          [
            {
              id: "issue-1-example",
              pattern: "08f8 ???? d744 56cc 0996 a8fc 8fee a6af"
            }
          ],
          { chunkSize: 7 }
        )
      )

      yield* _(
        Effect.sync(() => {
          expect(report.matches).toEqual([
            {
              signatureId: "issue-1-example",
              pattern: "08f8 ???? d744 56cc 0996 a8fc 8fee a6af",
              matchedHex: "08f8 1234 d744 56cc 0996 a8fc 8fee a6af",
              offset: 1
            },
            {
              signatureId: "issue-1-example",
              pattern: "08f8 ???? d744 56cc 0996 a8fc 8fee a6af",
              matchedHex: "08f8 abcd d744 56cc 0996 a8fc 8fee a6af",
              offset: 18
            }
          ])
        })
      )
    }))

  it.effect("stops early when max-matches limit is reached", () =>
    Effect.gen(function*(_) {
      const report = yield* _(
        readScanReport(
          [0xAA, 0xAA, 0xAA, 0xAA],
          [{ id: "repeat", pattern: "AA" }],
          { chunkSize: 2, maxMatches: 2 }
        )
      )

      yield* _(
        Effect.sync(() => {
          expect(report.matches).toHaveLength(2)
          expect(report.truncated).toBe(true)
        })
      )
    }))
})
