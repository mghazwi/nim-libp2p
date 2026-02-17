## Mix + Kad Get Example
## aim of this is a to do a simple example of doing a `getValue` through mix
## similar to flows in `tests/libp2p/kademlia/test_get.nim` and `examples/mix_ping.nim`

{.used.}

import chronicles, chronos, results
import std/[sequtils, strformat]
import stew/byteutils
import
  ../libp2p/[
    protocols/mix,
    protocols/mix/mix_protocol,
    protocols/mix/curve25519,
    protocols/kademlia,
    peerstore,
    multiaddress,
    switch,
    builders,
    multihash,
    crypto/crypto,
    crypto/secp,
  ]

const
  NumMixNodes = 10
  NumKadNodes = 3
  KadBasePort = 7400
  MixKadGetCodec = "/examples/mix-kad-get/1.0.0"
  MaxMsgSize = 4096

proc createSwitch(
    multiAddr: MultiAddress, libp2pPrivKey: Opt[SkPrivateKey] = Opt.none(SkPrivateKey)
): Switch =
  var rng = newRng()
  let skkey = libp2pPrivKey.valueOr(SkKeyPair.random(rng[]).seckey)
  let privKey = PrivateKey(scheme: Secp256k1, skkey: skkey)
  newStandardSwitchBuilder(privKey = Opt.some(privKey), addrs = multiAddr).build()

proc setupKadNodes(numNodes: int): seq[KadDHT] =
  var nodes: seq[KadDHT] = @[]

  for i in 0 ..< numNodes:
    let nodeAddr = MultiAddress.init(fmt"/ip4/127.0.0.1/tcp/{KadBasePort + i}").tryGet()
    let sw = createSwitch(nodeAddr)
    sw.peerInfo.addrs = @[nodeAddr]

    let cfg = KadDHTConfig.new(timeout = 1.seconds, quorum = 1, replication = 3)

    let kad = KadDHT.new(sw, @[], cfg)
    sw.mount(kad)
    nodes.add(kad)

  nodes

proc connectKadPeers(kad1, kad2: KadDHT) =
  discard kad1.rtable.insert(kad2.switch.peerInfo.peerId)
  discard kad2.rtable.insert(kad1.switch.peerInfo.peerId)

  kad1.switch.peerStore[AddressBook][kad2.switch.peerInfo.peerId] =
    kad2.switch.peerInfo.addrs
  kad2.switch.peerStore[AddressBook][kad1.switch.peerInfo.peerId] =
    kad1.switch.peerInfo.addrs

# connect all kad nodes
proc fullyConnectKad(nodes: seq[KadDHT]) =
  for i in 0 ..< nodes.len:
    for j in i + 1 ..< nodes.len:
      connectKadPeers(nodes[i], nodes[j])

type MixKadGetGateway = ref object of LPProtocol
  kad: KadDHT

# gateway to handle the get request, this should be the exit layer somehow. 
proc newMixKadGetGateway(kad: KadDHT): MixKadGetGateway =
  let proto = MixKadGetGateway(kad: kad)
  proto.codec = MixKadGetCodec

  proc handle(conn: Connection, _: string) {.async: (raises: [CancelledError]).} =
    try:
      # request is just the kad key bytes.
      let key = await conn.readLp(MaxMsgSize)
      if key.len == 0:
        await conn.writeLp(@[0.byte] & "missing key".toBytes())
        return

      let getRes = await kad.getValue(key, quorumOverride = Opt.some(1))
      if getRes.isOk:
        await conn.writeLp(@[1.byte] & getRes.get().value)
      else:
        await conn.writeLp(@[0.byte] & getRes.error().toBytes())
    except LPStreamError as exc:
      error "gateway stream error", err = exc.msg

  proto.handler = handle
  proto

proc mixKadGetSimulation() {.async: (raises: [Exception]).} =
  let mixNodeInfos = MixNodeInfo.generateRandomMany(NumMixNodes)
  var mixSwitches: seq[Switch] = @[]
  var mixProtos: seq[MixProtocol] = @[]

  for nodeInfo in mixNodeInfos:
    let sw = createSwitch(nodeInfo.multiAddr, Opt.some(nodeInfo.libp2pPrivKey))
    let mixProto = MixProtocol.new(nodeInfo, sw)
    mixProto.nodePool.add(mixNodeInfos.includeAllExcept(nodeInfo))
    mixProto.registerDestReadBehavior(MixKadGetCodec, readLp(MaxMsgSize))
    sw.mount(mixProto)

    mixSwitches.add(sw)
    mixProtos.add(mixProto)

  defer:
    await mixSwitches.mapIt(it.stop()).allFutures()

  let kads = setupKadNodes(NumKadNodes)
  defer:
    await kads.mapIt(it.switch.stop()).allFutures()

  let gatewayKad = kads[1]
  let publisherKad = kads[0]
  let gatewayProto = newMixKadGetGateway(gatewayKad)
  gatewayKad.switch.mount(gatewayProto)

  await mixSwitches.mapIt(it.start()).allFutures()
  await kads.mapIt(it.switch.start()).allFutures()
  fullyConnectKad(kads)

  let senderMix = mixProtos[0]

  let key = MultiHash.digest("sha2-256", "libp2p-mix-get".toBytes()).get().toKey()
  let value = "contentExample".toBytes()

  # Publish once in Kad, then only do anonymous get through gateway.
  (await publisherKad.putValue(key, value)).expect("publisher cant store value")

  # get through mix -> gateway -> Kad getValue
  let getConn = senderMix
    .toConnection(
      MixDestination.init(gatewayKad.switch.peerInfo.peerId, gatewayKad.switch.peerInfo.addrs[0]),
      MixKadGetCodec,
      MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
    )
    .expect("cant build get connection")

  await getConn.writeLp(key)
  let getResp = await getConn.readLp(MaxMsgSize)
  await getConn.close()

  if getResp.len == 0:
    raiseAssert "get returned empty response"

  if getResp[0] != 1.byte:
    raiseAssert "get failed: " & string.fromBytes(getResp[1 ..^ 1])

  let discoveredValue = getResp[1 ..^ 1]
  if discoveredValue != value:
    raiseAssert "get returned wrong value"

  info "Anonymous kad get via gateway succeeded",
    key = key,
    discoveredValue = string.fromBytes(discoveredValue)

when isMainModule:
  waitFor(mixKadGetSimulation())
