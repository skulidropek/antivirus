import fs from "node:fs"
import path from "node:path"
import { performance } from "node:perf_hooks"

import { describe, expect, it } from "@effect/vitest"
import { Effect } from "effect"

import { scanFile } from "../src/core/scanner.js"
import { compileSignatures } from "../src/core/signature.js"

const KPI_TIMEOUT_MS = 4000

const resolveKpiFilePath = (): string =>
  process.env.KPI_FILE_PATH ?? path.resolve(process.cwd(), "../../.downloads/1Gb.dat")

describe("scanner performance KPI", () => {
  it.effect("scans 1GB with two wildcard signatures in <= 4 seconds", () =>
    Effect.gen(function*(_) {
      const filePath = resolveKpiFilePath()

      yield* _(
        Effect.sync(() => {
          expect(fs.existsSync(filePath)).toBe(true)
        })
      )

      const signatures = compileSignatures([
        {
          id: "sig1",
          pattern: "2010 ???? 9b0b ???? 9a2b ???? 7f41 ????"
        },
        {
          id: "sig2",
          pattern: "452f ???? 763b ???? 8985 ???? 8892 ????"
        }
      ])

      const startedAt = performance.now()

      const report = yield* _(
        Effect.tryPromise({
          try: () =>
            scanFile(filePath, signatures, {
              chunkSize: 128 * 1024 * 1024
            }),
          catch: (error) => error instanceof Error ? error : new Error(String(error))
        })
      )

      const elapsedMs = performance.now() - startedAt

      yield* _(
        Effect.sync(() => {
          expect(report.bytesScanned).toBeGreaterThanOrEqual(1024 * 1024 * 1024)
          expect(report.matches.length).toBeGreaterThan(0)
          expect(elapsedMs).toBeLessThanOrEqual(KPI_TIMEOUT_MS)
        })
      )
    }))
})
