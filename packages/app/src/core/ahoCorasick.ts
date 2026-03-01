import type { CompiledSignature } from "./signature.js"

interface Node {
  readonly transitions: Map<number, number>
  fail: number
  readonly outputs: number[]
}

const createNode = (): Node => ({
  transitions: new Map<number, number>(),
  fail: 0,
  outputs: []
})

export class AnchorAutomaton {
  private constructor(private readonly nodes: ReadonlyArray<Node>) {}

  static build(signatures: ReadonlyArray<CompiledSignature>): AnchorAutomaton {
    const nodes: Node[] = [createNode()]

    signatures.forEach((signature, signatureIndex) => {
      if (signature.anchor.length === 0) {
        throw new Error(`Signature ${signature.id} does not have an anchor`)
      }

      let currentNode = 0

      for (const byte of signature.anchor) {
        const nextNode = nodes[currentNode]?.transitions.get(byte)

        if (nextNode !== undefined) {
          currentNode = nextNode
          continue
        }

        const newNodeIndex = nodes.length
        nodes[currentNode]?.transitions.set(byte, newNodeIndex)
        nodes.push(createNode())
        currentNode = newNodeIndex
      }

      nodes[currentNode]?.outputs.push(signatureIndex)
    })

    const queue: number[] = []

    for (const transitionTarget of nodes[0]?.transitions.values() ?? []) {
      queue.push(transitionTarget)
      const node = nodes[transitionTarget]
      if (node !== undefined) {
        node.fail = 0
      }
    }

    for (let head = 0; head < queue.length; head += 1) {
      const current = queue[head]
      const currentNode = nodes[current]

      if (currentNode === undefined) {
        continue
      }

      for (const [byte, next] of currentNode.transitions) {
        queue.push(next)

        let failureState = currentNode.fail

        while (failureState !== 0 && !nodes[failureState]?.transitions.has(byte)) {
          failureState = nodes[failureState]?.fail ?? 0
        }

        const fallback = nodes[failureState]?.transitions.get(byte)
        const nextNode = nodes[next]

        if (nextNode === undefined) {
          continue
        }

        nextNode.fail = fallback ?? 0
        nextNode.outputs.push(...(nodes[nextNode.fail]?.outputs ?? []))
      }
    }

    return new AnchorAutomaton(nodes)
  }

  forEachHit(
    data: Uint8Array,
    onHit: (signatureIndex: number, anchorEnd: number) => void
  ): void {
    let state = 0

    for (let index = 0; index < data.length; index += 1) {
      const byte = data[index]

      if (byte === undefined) {
        continue
      }

      while (state !== 0 && !this.nodes[state]?.transitions.has(byte)) {
        state = this.nodes[state]?.fail ?? 0
      }

      const transition = this.nodes[state]?.transitions.get(byte)
      state = transition ?? 0

      for (const signatureIndex of this.nodes[state]?.outputs ?? []) {
        onHit(signatureIndex, index)
      }
    }
  }
}
