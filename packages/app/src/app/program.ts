import { Console, Effect } from "effect"

import { compileSignatures } from "../core/signature.js"
import { scanFile, type ScanReport } from "../core/scanner.js"
import { readCliCommand } from "../shell/cli.js"

const toError = (error: unknown): Error =>
  error instanceof Error ? error : new Error(String(error))

const renderTextReport = (report: ScanReport): string => {
  const lines = [
    `File: ${report.filePath}`,
    `Bytes scanned: ${report.bytesScanned}`,
    `Signatures: ${report.signaturesScanned}`,
    `Matches: ${report.matches.length}`,
    `Duration: ${report.durationMs.toFixed(2)} ms`
  ]

  if (report.truncated) {
    lines.push("Search stopped early because max-matches limit was reached")
  }

  if (report.matches.length === 0) {
    lines.push("No matches found")
    return lines.join("\n")
  }

  lines.push("Detected signatures:")

  for (const match of report.matches) {
    lines.push(`- ${match.signatureId} at offset 0x${match.offset.toString(16)} (${match.offset})`)
  }

  return lines.join("\n")
}

export const program = Effect.gen(function* (_) {
  const command = yield* _(readCliCommand)

  if (command.kind === "help") {
    yield* _(Console.log(command.message))
    return command.message
  }

  const compiledSignatures = yield* _(
    Effect.try({
      try: () => compileSignatures(command.signatures),
      catch: toError
    })
  )

  const scanReport = yield* _(
    Effect.tryPromise({
      try: () => {
        const scanOptions = command.maxMatches === undefined
          ? { chunkSize: command.chunkSize }
          : { chunkSize: command.chunkSize, maxMatches: command.maxMatches }

        return scanFile(command.filePath, compiledSignatures, scanOptions)
      },
      catch: toError
    })
  )

  const output = command.json
    ? JSON.stringify(scanReport, null, 2)
    : renderTextReport(scanReport)

  yield* _(Console.log(output))

  return output
})
