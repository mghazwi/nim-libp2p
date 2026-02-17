## Mix + Kad getProviders Example
## aim of this is a to do a simple example of doing a `getProviders` through mix
## 

{.used.}

import chronicles, chronos, results
import std/[sequtils, strformat, strutils, sets]
import stew/byteutils
import
  ../libp2p/[
    protocols/mix,
    protocols/mix/mix_protocol,
    protocols/mix/curve25519,
    protocols/kademlia,
    peerid,
    peerstore,
    multiaddress,
    switch,
    builders,
    multihash,
    dial,
    crypto/crypto,
    crypto/secp,
  ]

const
  NumMixNodes = 10
  NumKadNodes = 3
  KadBasePort = 7400
  MixKadGetProvidersCodec = "/examples/mix-kad-getproviders/1.0.0"
  MaxLookupMsgSize = 4096

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

    let cfg = KadDHTConfig.new(timeout = 1.seconds, replication = 3)

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

type MixKadGetProvidersGateway = ref object of LPProtocol
  kad: KadDHT

# gateway to handle the getproviders request, this should be done at the exit. 
proc newMixKadGetProvidersGateway(kad: KadDHT): MixKadGetProvidersGateway =
  ## Request: key bytes.
  ## Response: status + comma separated provider peer IDs.
  let proto = MixKadGetProvidersGateway(kad: kad)
  proto.codec = MixKadGetProvidersCodec

  proc handle(conn: Connection, _: string) {.async: (raises: [CancelledError]).} =
    try:
      let key = await conn.readLp(MaxLookupMsgSize)
      let providers = await kad.getProviders(key)

      var providerIds: seq[string] = @[]
      for provider in providers.toSeq():
        let pid = PeerId.init(provider.id).valueOr:
          continue
        providerIds.add($pid)

      await conn.writeLp(@[1.byte] & providerIds.join(",").toBytes())
    except DialFailedError as exc:
      try:
        await conn.writeLp(@[0.byte] & ("dial failed: " & exc.msg).toBytes())
      except LPStreamError as streamExc:
        error "gateway getProviders dial+stream error",
          dialErr = exc.msg,
          streamErr = streamExc.msg
    except LPStreamError as exc:
      error "gateway getProviders stream error", err = exc.msg

  proto.handler = handle
  proto

proc mixKadGetProvidersSimulation() {.async: (raises: [Exception]).} =
  let mixNodeInfos = MixNodeInfo.generateRandomMany(NumMixNodes)
  var mixSwitches: seq[Switch] = @[]
  var mixProtos: seq[MixProtocol] = @[]

  for nodeInfo in mixNodeInfos:
    let sw = createSwitch(nodeInfo.multiAddr, Opt.some(nodeInfo.libp2pPrivKey))
    let mixProto = MixProtocol.new(nodeInfo, sw)
    mixProto.nodePool.add(mixNodeInfos.includeAllExcept(nodeInfo))
    mixProto.registerDestReadBehavior(MixKadGetProvidersCodec, readLp(MaxLookupMsgSize))
    sw.mount(mixProto)

    mixSwitches.add(sw)
    mixProtos.add(mixProto)

  defer:
    await mixSwitches.mapIt(it.stop()).allFutures()

  let kads = setupKadNodes(NumKadNodes)
  defer:
    await kads.mapIt(it.switch.stop()).allFutures()

  let gatewayKad = kads[1]
  let providerKad = kads[2]

  let gatewayProto = newMixKadGetProvidersGateway(gatewayKad)
  gatewayKad.switch.mount(gatewayProto)

  await mixSwitches.mapIt(it.start()).allFutures()
  await kads.mapIt(it.switch.start()).allFutures()
  fullyConnectKad(kads)

  # make key and announce one Kad node as provider for it.
  let contentKey = MultiHash.digest("sha2-256", "libp2p-provider-key".toBytes()).get().toKey()
  await providerKad.addProvider(contentKey)

  # Anonymous request through mix to gateway getProviders handler.
  let conn = mixProtos[0]
    .toConnection(
      MixDestination.init(gatewayKad.switch.peerInfo.peerId, gatewayKad.switch.peerInfo.addrs[0]),
      MixKadGetProvidersCodec,
      MixParameters(expectReply: Opt.some(true), numSurbs: Opt.some(byte(1))),
    )
    .expect("could not build mix connection")

  await conn.writeLp(contentKey)
  let response = await conn.readLp(MaxLookupMsgSize)
  await conn.close()

  if response.len == 0:
    raiseAssert "empty provider response"

  if response[0] != 1.byte:
    raiseAssert "gateway provider lookup failed"

  let providersCsv = string.fromBytes(response[1 ..^ 1])
  let providers =
    if providersCsv.len == 0: @[] else: providersCsv.split(",")

  if $providerKad.switch.peerInfo.peerId notin providers:
    raiseAssert "expected provider was not discovered"

  info "Anonymous getProviders via gateway succeeded",
    key = contentKey,
    providers = providers

when isMainModule:
  waitFor(mixKadGetProvidersSimulation())
