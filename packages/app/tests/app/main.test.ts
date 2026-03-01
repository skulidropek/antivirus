import { describe, expect, it } from "@effect/vitest"
import { Effect } from "effect"
import { vi } from "vitest"

import { program } from "../../src/app/program.js"
import { withTempBinaryFile } from "../helpers/temp-binary-file.js"

const withLogSpy = Effect.acquireRelease(
  Effect.sync(() => vi.spyOn(console, "log").mockImplementation(() => {})),
  (spy) =>
    Effect.sync(() => {
      spy.mockRestore()
    })
)

const withArgv = (nextArgv: ReadonlyArray<string>) =>
  Effect.acquireRelease(
    Effect.sync(() => {
      const previous = process.argv
      process.argv = [...nextArgv]
      return previous
    }),
    (previous) =>
      Effect.sync(() => {
        process.argv = previous
      })
  )

describe("CLI program", () => {
  it.effect("prints JSON report for detected signatures", () =>
    Effect.scoped(
      Effect.gen(function*(_) {
        const { filePath } = yield* _(
          withTempBinaryFile(
            "antivirus-program-test-",
            "payload.bin",
            [0xDE, 0xAD, 0x01, 0xBE, 0xEF]
          )
        )
        const logSpy = yield* _(withLogSpy)

        yield* _(
          withArgv([
            "node",
            "main",
            "scan",
            "--file",
            filePath,
            "--signature",
            "virus:DE AD ?? BE EF",
            "--json"
          ])
        )

        const output = yield* _(program)

        yield* _(
          Effect.sync(() => {
            const report = JSON.parse(output) as {
              readonly matches: ReadonlyArray<{
                readonly signatureId: string
                readonly matchedHex: string
                readonly offset: number
              }>
            }

            expect(report.matches).toEqual([
              {
                signatureId: "virus",
                pattern: "DE AD ?? BE EF",
                matchedHex: "dead 01be ef",
                offset: 0
              }
            ])
            expect(logSpy).toHaveBeenCalledTimes(1)
          })
        )
      })
    ))
})
