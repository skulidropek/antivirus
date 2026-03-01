import { describe, expect, it } from "vitest"

import { compileSignature, parseInlineSignature, parseSignatureList } from "../../src/core/signature.js"

describe("signature parser", () => {
  it("compiles wildcard bytes and chooses the longest concrete anchor", () => {
    const compiled = compileSignature({
      id: "wild",
      pattern: "DE AD ?? BE EF"
    })

    expect([...compiled.values]).toEqual([0xDE, 0xAD, 0x00, 0xBE, 0xEF])
    expect([...compiled.masks]).toEqual([0xFF, 0xFF, 0x00, 0xFF, 0xFF])
    expect(compiled.anchorOffset).toBe(0)
    expect([...compiled.anchor]).toEqual([0xDE, 0xAD])
  })

  it("supports nibble wildcards", () => {
    const compiled = compileSignature({
      id: "nibbles",
      pattern: "A? ?F C3"
    })

    expect([...compiled.values]).toEqual([0xA0, 0x0F, 0xC3])
    expect([...compiled.masks]).toEqual([0xF0, 0x0F, 0xFF])
    expect(compiled.anchorOffset).toBe(2)
    expect([...compiled.anchor]).toEqual([0xC3])
  })

  it("parses inline and file-based signatures", () => {
    const inline = parseInlineSignature("botnet:DE AD BE EF", 1)
    const fromFile = parseSignatureList(
      `# comment\nTrojan=AA BB CC\n11 22 ?? 44\n`,
      "file"
    )

    expect(inline).toEqual({ id: "botnet", pattern: "DE AD BE EF" })
    expect(fromFile).toEqual([
      { id: "Trojan", pattern: "AA BB CC" },
      { id: "file-1", pattern: "11 22 ?? 44" }
    ])
  })

  it("rejects signatures that have no concrete bytes", () => {
    expect(() =>
      compileSignature({
        id: "all-wild",
        pattern: "?? ??"
      })
    ).toThrow("Signature must contain at least one concrete byte")
  })
})
