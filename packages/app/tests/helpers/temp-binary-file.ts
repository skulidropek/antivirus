import fs from "node:fs"
import os from "node:os"
import path from "node:path"

import { Effect } from "effect"

interface TempBinaryFile {
  readonly directory: string
  readonly filePath: string
}

export const withTempBinaryFile = (
  prefix: string,
  fileName: string,
  bytes: ReadonlyArray<number>
) =>
  Effect.acquireRelease(
    Effect.sync<TempBinaryFile>(() => {
      const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix))
      const filePath = path.join(directory, fileName)
      fs.writeFileSync(filePath, Buffer.from(bytes))

      return { directory, filePath }
    }),
    ({ directory }) =>
      Effect.sync(() => {
        fs.rmSync(directory, { recursive: true, force: true })
      })
  )
