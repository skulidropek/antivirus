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
              offset: 0
            },
            {
              signatureId: "exact",
              pattern: "90 DE AD",
              offset: 5
            },
            {
              signatureId: "wildcard",
              pattern: "DE AD ?? BE EF",
              offset: 6
            }
          ])

          expect(report.truncated).toBe(false)
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
