#import "common/template.typ": cover_page, header, footer, setup_page

#cover_page(title: "Homework 2", date: "January 2024")

#pagebreak()

#show: setup_page

#set page("a4", header: header(title: "HW2"), footer: footer)
#counter(page).update(1)

#outline()
#pagebreak()

= CASTOR

#set enum(numbering: "1)")

// unfortunately typst does not allow running arbitrary programs, so we have to hardcode this here
#let md5_hashtable = (
  "50d02858": "045afeaef6d4b1b351aa35d50c84d424", // vv Bob
  "045afeaec7e2b366": "a762680130cabd8feb7fc68e50515a61", "a762680123f140ad": "1461c8e3718070f827086b6f541131ea", "1461c8e395294aec": "9cb546a7ff135ddd4643191c3dbbefc8", "9cb546a7a4745acb": "efe5033737345c91f2453871b3a1528b",
  //
  "07fd01d5": "0561a9ca01d3ba79ece8055b0d523147", // vv Alice
  "0561a9ca5a9d0480": "833f717633a2f7bb70c9d95403da966c", "833f717693aded1d": "c30c554bb3796b7e7c73906e26086adc", "c30c554bd97d3412": "707791877995a6b484fcea53ef21f265", "70779187414833e5": "ede9aa5fe7b69e13042ade7190c91136",
)

#let castor_hash(msg) = {
  md5_hashtable.at(msg).slice(0, count: 8) // truncate at 8
}

#let castor_solve(name, H, bk, fk) = {
  [Given a flow identifier of $H = #H$, #name has to verify the packet identifier $b_k$ using
    the flow authenticator as follows:]

  // recursion seems like the only way to have alignment,
  // as alignment only works within a single equation
  // and there might not exist a better way to merge equations
  let helper(bk, fk, i) = {
    if i <= 0 {
      let hash_rep = $h(b_k)$
      let hash = castor_hash(bk)
      return (hash_rep, hash, $   &#hash_rep = h(bk) = hash$)
    }

    let (last_hash_rep, last_hash, out) = helper(bk, fk, i - 1)
    let x = fk.at(i - 1)
    let hash_rep = $h(#last_hash_rep || x_#i)$
    let hash_input = last_hash + x
    let hash = castor_hash(hash_input)

    return (hash_rep, hash, $#out \
      &#hash_rep = h(#hash_input) = #hash$)
  }

  let (_, last_hash, out) = helper(bk, fk, fk.len())

  $ #out $

  if last_hash == H {
    [ Since the last hash matches $H$, #name forwards the packet. ]
  } else {
    [ #name does *NOT* forward the packet, as the last hash differs from $H$
      ($#last_hash #sym.eq.not #H$). ]
  }
}

+ #castor_solve(
    "Bob", "efe50337", "50d02858", ("c7e2b366", "23f140ad", "95294aec", "a4745acb"),
  )

+ #castor_solve(
    "Alice", "12328e72", "07fd01d5", ("5a9d0480", "93aded1d", "d97d3412", "414833e5"),
  )

#pagebreak()

= Secure Data Forwarding

#set enum(numbering: "a)")

+ If end-to-end authentication and integrity is provided by an upper layer, $F$ cannot
  modify any data packets or inject new ones (except perhaps as discussed below)
  without such attacks being detected.

  However, since the mechanisms are only in place at a higher layer, $F$ can still
  modify any content that is not covered by such measures, such as packet metadata
  relating to lower layers, which may or may not have significant impact.
  Additionally, depending on the upper layer's implementation, it may be possible
  for $F$ to perpetrate a relay attack where $F$ re-sends at a later time a valid
  message it had previously intercepted. This relay attack is possible unless the
  higher layer guarantees message freshness too (for instance, by including a
  nonce in all messages).

  It should also be noted that, if the upper layer does not also provide
  end-to-end encryption (since that is not explicitly mentioned in the question
  assumptions), $F$ can still read any messages it intercepts, so confidentiality
  is not protected in any form.

  Finally, also depending on the upper layers' implementation, it may be possible
  for $F$ to drop messages entirely without detection (and the potential lack of
  confidentiality makes surgical dropping more effective and easier to confuse
  with regular network disruptions), unless there is some sort of authenticated
  acknowledgement system in place#footnote[If acknowledgements are not authenticated, $F$ can simply forge a fake one.] (allowing
  one party to detect the attack) or message serialization is used (if all
  messages are tagged sequentially, the recipient can infer a message has been
  dropped). Evidently, these protections would only work if their authenticity,
  integrity and freshness was also guaranteed by the upper layers implementing
  them.

  Nevertheless, even without this sort of mechanisms that would detect message
  dropping, integrity is verified at a higher layer and those verified upper-level
  messages ($M^arrow.t$) might not be mapped one-to-one with the lower-level
  messages ($M_arrow.b$) that $F$ intercepts and processes - for example, if $M^arrow.t$ are
  larger in size than $M_arrow.b$, one $M^arrow.t$ could be spread over several $M_arrow.b$;
  alternatively, for the opposite scenario, one $M_arrow.b$ could accommodate
  several $M^arrow.t$ sent at once. The crucial point to realize here is that $F$ can
  only deal with $M_arrow.b$ messages, but (unless as described above) they can
  only drop units of $M^arrow.t$, which can be a disparity that makes any attacks
  much harder to manage (for instance, in the first case described, $F$ would need
  to collect several $M_arrow.b$ until it had a complete $M^arrow.t$ to then
  analyze and potentially drop in its entirety). Only whole, integer units of $M^arrow.t$ could
  be dropped, as otherwise the recipient would trivially detect an integrity
  fault.

+ As described above, packet dropping is possible under specific circumstances and
  depending on the upper layers' implementation. On the other hand, packet
  modification would be detected as an integrity fault, except perhaps for in the
  concrete case of removing entire units of higher-level messages ($M^arrow.t$),
  which does not necessarily correspond to dropping a lower-level $M_arrow.b$ packet:
  for example, for a packet $m_(arrow.b,1) = m^(arrow.t,1) || m^(arrow.t,2) || m^(arrow.t, 3)$ that $F$ intercepted,
  it could potentially modify it to become $m'_(arrow.b,1) = m^(arrow.t,1) || m^(arrow.t,3)$ without
  being detected (if no other mechanisms are in place).

  It should be noted, however, that even if dropping is detected by the
  communicating parties, there is nothing they can do in this case to prevent it,
  unless the end hosts' upper layer (which detected the fault) can somehow flag it
  down to the routing layer and the latter can, in turn, consider that route to be
  down and select an alternative. This also assumes that intermediary nodes will
  respect the route chosen by the original packet sender, which might not be the
  case. Alternatively, the host can try to propagate route failure information. It
  would also be impossible to know in which specific intermediary the fault took
  place, and whether it happened for the original message or for the ACK.

  In addition, as mentioned above, metadata pertaining to layers below the one
  providing integrity validation could be vulnerable to undetected modification,
  though the magnitude of impact that could stem from such an attack would vary
  depending on the specific context.

+ With authenticated feedback in place, $F$ cannot forge an acknowledgement
  message, which means that any messages dropped would be detected (unless all
  ACKs are identical and do not guarantee freshness by referring to a specific
  message ID and/or including a nonce, in which case $F$ could still perform a
  replay attack). Nevertheless, as discussed above, in most cases there is nothing
  the legitimate nodes can do to remediate against their packets being dropped,
  even if they detect it happening.

+ Assuming that $F$ drops all packets, unconditionally, we have that:

  - If $A$ forwards the packet to $B$, the latter will select route $B -> E -> G$ (cost
    11), and the packet will be received (does not pass through $F$);
  - If $A$ forwards the packet to $C$, the latter will select route $C -> #square[F] -> E -> G$ (cost
    8), and the packet will be dropped (passes through $F$).

  Thus, the fraction of $A -> G$ packets that will be delivered corresponds to the
  fraction of packets $A$ forwards to $B$ and not to $C$ - given the $50%$ probability
  described, this means a fraction of $1/2$.

+ Following a reasoning analogous to the above, we have:

  $ f_(A,C) = underbrace(1/2, A -> B) + underbrace(1/2, A -> C) dot.c underbrace(2/3, C -> E\/B) = 5/6 approx 83.3% $

+ In the same manner:

  $ f_(A,B,C) = underbrace(1/2, A -> B) (underbrace(2/3, B -> D\/E) + underbrace(1/3, B -> C) dot.c underbrace(1/2, C -> E)) + underbrace(1/2, A -> C) dot.c underbrace(2/3, C -> B\/E) = 5/12 + 1/3 = 3/4 = 75% $

+ In order to compromise $A -> G$ communications, an attacker could:

  - Compromise both $B$ and $C$, leaving no alternative routes for communication; or
  - Compromise $D$, $E$, and $F$, for the same reason as above (but might be less
    evident for $A$ as it does not have direct contact with them).

  Any other options would rely on other, legitimate nodes routing in a specific
  fashion, which would be an assumption incompatible with the absolute certainty
  desired for this scenario.

#pagebreak()

= Birthdays

#set enum(numbering: "1)")

+ The birthday paradox is a probability phenomena which describes that within a
  group of just 23 people, there is a $>50%$ probability of finding 2 people with
  the same birthday. In generic terms, the birthday paradox refers to the fact
  that it is non-intuitively probable for there to be a collision between two
  distinct events. Though correct, this may seem counter-intuitive because $N$ to $N$ matching
  is often confused with $N$ to $1$ matching (i.e., trying to find someone within
  the group with a birthday on a specific date, which would be much less
  probable).

+ Traditional DNS cache poisoning attacks work by trying to mislead a DNS server $D$
  into populating its cache with a false entry, such as having the server believe
  the name `bank.com` has an `NS` record pointing to an attacker-controlled
  resolver $T$ (and this would be cached for the duration of the record's TTL).
  Victim end-hosts would then query $D$ for `bank.com` and it would resolve the
  name recursively by querying $T$, which is attacker-controlled and would respond
  with a forged `A` record for `bank.com` pointing to an attacker-controlled IP
  address (which would also be cached by $D$, and by the victim).

  In this traditional attack, a recursive resolver $D$ would be queried by the
  attacker for a bogus `abc123.bank.com` subdomain (or any such variation) which
  would not be in $D$'s cache and force it to recurse by querying another server.
  The attacker would then immediately flood $D$ with $k$ forged responses (stating
  the subdomain does not exist and naming $T$ as the `NS` authority for `bank.com`),
  in hopes that one of them would be accepted by $D$ before the legitimate
  response. The problem here, besides in terms of speed, lies in matching the
  response's _Query ID_ field with the request's, which the attacker does not
  know; since a `QID` has 16 bits, this makes the probability of a successful
  guess $P = k/(2^(16))$.

  The BIND birthday attack works by sending $n$ queries to the targeted DNS server $D$ (rather
  than just one), while also sending $n$ spoofed responses to that server. As
  previously described for the birthday scenario, this makes it much more probable
  for the attacker to succeed, as it is only necessary for there to be a `QID` collision
  between any one of the $n$ queries and one of the $n$ responses, rather than the
  previous case of needing a collision between one of the $k$ responses with the
  specific `QID` value associated with the single query made.

  #v(1fr) // page break

+ Recalling the formula from the Secureworks article, we can calculate the
  probability of a collision in function of the number of queries/replies ($n$)
  and the number of possible QID values ($t$):

  $ P_"collision" = 1 - (1 - 1/t)^((n dot (n-1))/2) $

  Considering that the QID range is $[0, 2^16 [$ (i.e., $t = 2^16$ possible
  values) we want to find $n$ such that:

  $
    P_"collision" >= 0.25
      & => 1 - (1-1/(2^16))^((n dot (n-1)) /2) >= 0.25 \
      & => (1 - 1/2^16)^((n(n-1))/2) <= 0.75 \
      & => ln((1 - 1/2^16)^((n(n-1))/2)) <= ln(0.75) \
      & => (n(n-1))/2 dot ln(1 - 1/2^16) <= ln(0.75) \
      & => n(n-1) >= 2 dot ln(0.75)/ln(1 - 1/2^16) \
      & => n^2 - n - 2 dot ln(0.75)/ln(1 - 1/2^16) >= 0 \
      & => #rect[$n >= 194.7$] or cancel(cross: #true, n <= -193.7)
  $

  Since $n$ must be a positive integer, the lowest such integer that satisfies the
  inequation is $n = 195$. Thus, 195 spoofed replies are required to achieve a
  chance of collision of at least 25%.

#pagebreak()

= DNS Attack

#set enum(numbering: "1)")

+ The attacker can perform a DNS amplification attack by spoofing the DNS query IP
  packet's source address field to be `203.130.1.5` (the victim's IP address) so
  that the DNS server, upon resolving the query, will respond to the victim. The
  importance of this attack is that each response packet sent to the victim is
  much larger than each request packet sent by the attacker ($1200 "Bytes" "vs" 64 "Bytes"$),
  meaning that the attacker can easily overwhelm the victim (and/or the link
  connecting the victim to the rest of the network) while only spending a fraction
  of their own bandwidth. As the name implies, an amplification attack allows the
  perpetrator to amplify its effects in relation to the effort applied.

+ No, DNSSEC cannot prevent this attack, as it only protects the authenticity and
  integrity of specific records. This attack does not hinge on any sort of forged
  DNS records, as it depends only on responses being larger than queries, and
  DNSSEC does not help in that respect (if anything, DNSSEC could perhaps lead to
  even larger response sizes for signatures to be included). Additionally, DNSSEC
  does not authenticate queries (only responses), so it would not stop the
  attacker from spoofing the victim.

  A possible countermeasure would be to require DNS to take place exclusively over
  TCP (rather than UDP), as the latter is a connection-less protocol but the
  former is not, and thus would not allow the attacker to spoof the victim's IP
  address: they would not be able to complete the TCP three-way handshake as the
  server's first message would be sent to the victim and not the attacker.

+ In this scenario, the amplification factor is:

  $ f = "size"_"response"/"size"_"request" = (1200 "Bytes")/(64 "Bytes") = 18.75 $

  It is important for the attacker for the amplification to be as high as
  possible, so that they can have a greater chance of exhausting the victim's
  bandwidth and computational resources without using too much of their own. If
  the amplification factor is too low, the malicious actor might be dissuaded and
  try to find another vulnerability or victim instead.

+ No, the described firewall rules would not prevent this sort of attack, as they
  allow the private resolver to send outgoing packets even for `NEW` connections,
  meaning that the attacker could send it spoofed queries and the resolver would
  be able to send the response to the victim.

  A solution here could be for the private resolver to only respond to queries
  with a source address within the local network it is intended to serve (in this
  case, `192.168.1.0/24`). This would still allow the attacker to target local
  victims, but if that is a concern, DNS over TCP could be enforced as described
  above to prevent spoofing altogether, despite the potential performance overhead
  it implies.

+ An administrator in the victim's network can introduce firewall rules `IN DNS ESTABLISHED ACCEPT` and `OUT DNS NEW/ESTABLISHED ACCEPT` with
  a `DROP-ALL` default policy, which would prevent any unsolicited DNS responses
  from entering the network, no matter the number of attackers. However, this
  would only protect that network itself, and an attacker might still be able to
  exhaust a link before the firewall.

+ An administrator of the public resolver can prevent spoofing by requiring DNS
  over TCP, as described above (or a higher-level solution such as DNS over TLS or
  DNS over HTTPS, which use TCP/QUIC). Otherwise, if that is not possible, they
  could potentially mitigate the problem by reducing the amplification factor,
  configuring the response size to be smaller.

#pagebreak()

= Near Field Communication Attacks

#set enum(numbering: "1)")

+ Considering that $C$ is a resource-constrained device, we should strive to avoid
  multi-step communications that require round-trips and maintaining state within
  the card, which perhaps would not be realistic. In addition, given that $C$ is
  bound to a certificate known to $R$ but the opposite is not true (nor would it
  make much sense due to $C$'s lack of resources and the possibility of there
  existing several readers), we assume that it is only relevant for the reader to
  be able to authenticate the card, but not vice-versa. Finally, due to asymmetric
  cryptography being much more computationally expensive than symmetric, our goal
  should be to use the latter and reduce the use of the former as much as possible
  (but not entirely as it is the only way to provide effective card
  authentication; $R$ can extract
  $"Pub"_C$ from $"Cert"_C$). A possible augmented protocol could then be as
  follows:

  $ R:     & "generate a random" k \
  R:     & a <- "Enc"_"Pub"_C (k) \
  R:     & b <- E_k (m_1) \
  R:     & h_1 <- "HMAC"_k (N_R, a, b) \
  R -> C:& (N_R, a, b, h_1) \
  C: & k <- "Dec"_"Priv"_C (a) \
  C: & h == "HMAC"_k (N_R, a, b) \
  C: & m_1 <- D_k (b) \
  C:     & c <- E_k (m_2) \
  C: & h_2 <- "HMAC"_k (N_R, c) \
  C -> R:& (N_R, c, h_2) \
  R: & h_2 == "HMAC"_k (N_R, c) \
  R: & N_R == N_R \
  R:     & "Estimate RTT and" d(R, C) $

  where $"HMAC"_K$ is the HMAC function as defined in RFC 2104 using key $K$, and $m_1$ and $m_2$ refer
  to the messages from the original protocol this one augments.

  This protocol guarantees card-to-reader authentication and card non-repudiation
  as only $C$ would have $"Priv"_C$ with which to decrypt $a$ and obtain the
  symmetric key $k$ with which to generate a valid HMAC for the response message.
  That same HMAC in both messages (covering the entirety of the message) is what
  guarantees integrity, amd confidentiality is ensured because both $m_1$ and $m_2$ are
  transmitted encrypted with key $k$ which only the two legitimate parties have.
  Additionally, replay attacks are not possible since freshness is guaranteed by
  the inclusion of a per-exchange nonce in the request and response messages (with
  said nonce also being used as HMAC input). This protocol also has the advantage
  of not requiring any state to be persisted on the card (except for its private
  key), which is an invaluable quality when considering a resource-constrained
  device.

  #v(1fr) // page break

+ No, it is not possible for the reader to get accurate estimations of $d(R, C)$,
  as physical neighborhood does not always imply communication neighborhood#footnote[P. Papadimitratos et al., "Secure neighborhood discovery: a fundamental element
    for mobile ad hoc networking," in IEEE Communications Magazine, vol. 46, no. 2,
    pp. 132-139, February 2008, doi: 10.1109/MCOM.2008.4473095.], meaning that a
  malicious actor can perpetrate an attack (such as the one described below) to
  mislead the reader into believing $d(R, C)$ is shorter than in reality. Accurate
  estimations would only be possible, in this specific scenario, under the
  assumption that any physical distance is representative - for example, that the
  full range of the reader (i.e., a sphere centered around $R$ with a $30m$ radius)
  is clear of any obstructions, wireless communication interferences, and
  non-wireless communication means.

  Nevertheless, it should be noted that the protocol does impose an effective
  upper bound on $d(R, C)$ - that is, an attacker can also mislead $R$ into
  believing the communication distance is shorter than in reality, but never that
  the distance is larger. By measuring the signal round-trip time and multiplying
  it by the signal propagation speed, $R$ obtains an estimation for $d(R, C)$ that
  is reasonable in the absence of malicious actors (or unaccounted external
  forces) and that in any case is an upper bound for the real distance. However,
  it should be considered whether the cryptographic computations described above
  (as well as any others required for $C$ to compute $m_2$) take up a
  non-negligible amount of time, in which case a static approximation of such time
  should also be taken into account during this calculation (otherwise, $C$ might
  measure this computation time and include it in the response to $R$ to aid with
  the calculation).

+ One way an attacker could mislead $R$ into believing $d(R, C)$ is shorter than
  in reality, would be implementing an out-of-band relay between $C$ and $R$, such
  as in the diagram below:

  #let diag_h = 20%
  #let diag_center(c) = block(height: diag_h, align(center + horizon, c))
  #figure([
    #columns(7, gutter: 0pt, [
      #diag_center(circle($R$))
      #colbreak()
      #diag_center(circle($T_1$))
      #colbreak()
      #diag_center(line(length: 30pt, stroke: (dash: "dashed")))
      #colbreak()
      #rect(height: diag_h, align(center + horizon, [Wall]))
      #colbreak()
      #diag_center(line(length: 30pt, stroke: (dash: "dashed")))
      #colbreak()
      #diag_center(circle($T_2$))
      #colbreak()
      #diag_center(circle($C$))
    ])
  ], caption: [Diagram of a possible attack.])

  where $T_1$ and $T_2$ are attacker-controlled relay devices that communicate via
  wire (out-of-band) through a wall, with such devices also communicating wireless
  with $R$ and $C$ respectively and simply forwarding each $R$/$C$ message in a
  wired fashion "through the wall", completely transparently and much faster than
  if $C$ and $R$ tried to communicate using wireless signals (going around the
  wall). This would lead $R$ into measuring a much smaller RTT, which in turn
  would mislead it into believing $d(R, C)$ is much shorter than the real
  communication distance (this is true even if $C$ is out of range, in which case
  we consider $d(R, C) = +infinity$).

  The protocol described above does not protect against this sort of "wormhole"
  attack, as it is not possible to account for such a disparity between physical
  and communication distance. However, it does protect against other types of
  relay attacks, as a nonce is included in the protocol messages preventing them
  from being accepted twice.

#pagebreak()

= IoT

#set enum(numbering: "1)")

+ The farm has the communicating IoT devices listed below, which can be assigned three generic categories according to their communication role within the network: *sensor*, *sink*, and *controller* (sensors send data to the sink, and the sink sends commands to controllers).

  - $M_1,dots,M_k$ soil moisture *sensors*
  - $C_1,dots,C_l$ climate *controllers*
  - $I_1,dots,I_m$ irrigation *controllers*
  - $"Dr"_1,dots,"Dr"_n$ drones (*sensors* and *controllers*, simultaneously)
  - $R_1,dots,R_o$ RFID readers (*sensors*)
  - $T_1,dots,T_p$ RFID tags (communicate with readers)
  - $S$, *sink* (i.e., the central server)

  For simplicity, it is assumed that the devices are laid out in a mesh network,
  that is, a Wireless Sensor Network as described in this course,
  and thus all devices are able to send/receive messages to/from the sink (i.e., there is always a path that allows it, potentially including more intermediaries). We also assume that secure route discovery is guaranteed, due to being out of the scope of this exercise.

+ The protocol is designed to prevent an attacker from reading and/or modifying measurements.
  It also prevents an attacker from deleting and/or reordering measurements without being detected.

  For devices that need to receive commands (i.e., controllers), the protocol must also prevent
  a malicious actor from initiating or altering commands.

  For both types of devices (i.e., sensors and controllers), the protocol ensures authenticity
  of the messages by making sure they cannot be forged as if coming from another party, through the
  use of a shared key only known to the device and the sink.

  Keeping in mind the restrictions associated with low-power IoT devices, to achieve these goals
  symmetric encryption is used for confidentiality, and Message Authentication Codes (MAC)
  for integrity and authenticity. Asymmetric cryptography was discarded for most communications
  because it is more computationally intensive than symmetric cryptography, though it is still used for the initial
  key establishment.
  In order to ensure measurements are not deleted and/or reordered, we will maintain
  a logic clock per sensor (effectively a clock), which increases with each measurement, along with
  a corresponding one on the sink; a timestamp approach was discarded due to the challenges of synchronizing time
  on such power-constrained devices.

  Given the unattended nature of these devices, in order to decrease the probability of an attacker
  compromising the cryptographic keys, the protocol must account for periodic key refreshing, without
  compromising previous or subsequent sessions.

  While this protocol will not focus on secure route discovery (as mentioned above), it is still important
  to note that the IoT devices can communicate with the sink through other devices, without losing any of
  the properties mentioned above, even if they are not in range.

+ Due to the resource constraints in IoT devices (both power consumption and available computational power),
  it is important to select low-power and efficient cryptographic algorithms for the protocol.
  For sending measurements to the sink and actions to controllers, using a symmetric cryptographic
  algorithm (in contrast to an asymmetric one) is an immediate choice: they use significantly less
  resources than their asymmetric counterparts.

  Based on available research#footnote[D. Saraiva et al., "PRISEC: Comparison of Symmetric Key Algorithms for IoT Devices," in Sensors (Basel), vol. 19, October 2019, doi: 10.3390/s19194312.], it is clear that the best option for data encryption, ensuring confidentiality,
  is to use hardware-accelerated AES; otherwise, if that is not available,
  the second best option outlined in the paper is ChaCha20-Poly1305.
  For the sake of simplicity, it is assumed hardware-accelerated AES is available, and
  therefore the protocol will use AES with a key-length of 256 bits.

  As for integrity/authenticity, both SHA-2 or SHA-3 could be used, as they are secure and
  well-established, though SHA-3 is not vulnerable to length extension attacks. From now on, it is assumed that the protocol uses SHA-3 512 bits through an HMAC
  function, as described in RFC 2104.

+ There are several different scenarios in which the involved parties may wish to communicate.
  As the requirements for these scenarios are different, multiple sub-protocols
  are presented below that are adequate for a specific circumstance.
  As previously mentioned, it is assumed that there is secure route discovery in the network, so
  a protocol for that is not detailed below.

  From now on, sensors and controllers will be generically referred to as _device_, $D$, when
  it applies to both.

  - *Initial Key Establishment ("pairing")*

    Before the devices can start communicating with the sink (and vice-versa), a symmetric key
    needs to be shared between them. This key is only to be known to the sink and to the device in question (i.e., there is a different key $K_(D_i\/S)$ for each sink-device pair).

    As to reduce the protocol's complexity, it is assumed that the IoT devices come preloaded with
    the sink's certificate (or, alternatively, that of a Certificate Authority that signs the sink's certificate -- though for the sake of
    simplicity, it is assumed below that the first option is true).

    #let key = $K_(D_i"/"S)$

    $
    &D_i:&& "generate random" key \
    &D_i:&& a <- "Enc"_"Pub"_S ("\"pair\"", D_i, key, N_D_i) \
    &D_i:&& b <- "HMAC"_key (a) \
    &D_i -> S:&& (a, b) \

    &S:&& b == "HMAC"_key (a) \
    &S:&& ("\"pair\"", D_i, key, N_D_i) <- "Dec"_"Priv"_S (a) \
    &S:&& c <- E_key ("\"key establishment\"", D_i, N_D_i - 1, N_S) \
    &S:&& d <- "HMAC"_key (c) \
    &S -> D_i:&& (c, d) \

    &D_i:&& d == "HMAC"_key (c) \
    &D_i:&& ("\"key establishment\"", D_i, N_D_i - 1, N_S) <- D_key (c) \
    &D_i:&& N_D_i - 1 == N_D_i - 1 \
    &D_i:&& e <- E_key ("\"key established\"", D_i, N_S - 1) \
    &D_i:&& f <- "HMAC"_key (e) \
    &D_i -> S:&& (e, f) \

    &S:&& f == "HMAC"_key (e) \
    &S:&& ("\"key established\"", D_i, N_S - 1) <- D_key (e) \
    &S:&& N_S - 1 == N_S - 1 \
    &S:&& "assume" key "as key with" D_i
    $

    This protocol has a drawback that needs to be addressed in the central server itself:
    the devices are not authenticated in the eyes of the server, since the former do not hold any certificate, meaning any attacker could start a pairing process with the server using anotheer device of their own. To prevent this,
    the server should only enter "pairing mode" when strictly necessary and the device ID of the device
    to be paired should be manually verified.

    Another important assumption made in this protocol is that the pairing process cannot be started
    for a device that is already paired - otherwise an attacker could overwrite its key in the server.

  - *Sensor*

    The sensor periodically sends messages back to the server, using the key they have established.
    To ensure packets are not reordered/dropped/replayed by a malicious actor, the information sent by the
    sensor has a sequence number of the measurement, $"Seq"_D_i$, allowing the sink to detect all of
    these attacks.

    $
    &D_i:&& c <- E_key (D_i, "Seq"_D_i, "<measurement data>") \
    &D_i -> S:&& (c, "HMAC"_key (c))
    $

  - *Controller*

    The sink can also send messages to the controllers, in order to execute commands/actions, using
    the key previously established. Here, it is imperative that the protocol is resistant to replay attacks,
    so the value of a logic clock is included in the message. The value of this clock is increased every
    time the sink sends a new message to the controllers (for simplicity, it is assumed that there is only one
    shared logic clock for all controllers; it does not impact functionality). When a controller receives
    a message from the sink, it checks if the received logic clock value is greater than the saved one -
    if so, it accepts the message and executes the action, and otherwise it silently discards it.

    $
    &S:&& c <- E_key (D_i, t^S_"logic clock", "<action data>") \
    &S -> D_i:&& (c, "HMAC"_key (c))
    $

  - *Periodic Key Refreshing*

    In order to attenuate the impact in the chance that a symmetric key is leaked and known to an attacker,
    all devices periodically refresh their keys with the sink. To prevent the attacker from getting
    the new key if it later obtains a previous key, the new one is encrypted using the sink's
    public key:

    $
    &D_i:&& "generate random" K'_(D_i\/S) \
    &D_i:&& c <- E_key (D_i, "\"key refresh\"", "Enc"_"Pub"_S (K'_(D_i"/"S))) \
    &D_i -> S:&& (c, "HMAC"_key (c))
    $

    It should be noted that no nonces are included in this message because the old key will immediately
    become invalid, therefore rendering any replay attack useless.

  - *En Route Re-Encryption*

    In order to limit the actions of an attacker that obtained the key of a device, our protocol implements
    _en route_ re-encryption, requiring an adversary to be a direct neighbor of the compromised device to be able
    to reliably modify messages.
    In order to achieve this, each device a message is hopped through re-encrypts it. Additionally, to attenuate the performance
    hit of this security measure, devices only re-encrypt messages with a certain probability $0 < p < 1$, simply
    forwarding it otherwise.

    Message re-encryption can be described as such:

    $
    &D_i -> D_j:&& "msg" \
    &D_j:&& c <- E_(K_(D_j"/"S)) (D_j, "msg") \
    &D_j -> D_k:&& (c, "HMAC"_(K_(D_j"/"S)) (c))
    $

+ To summarize the desired properties, confidentiality, integrity and authentication must all be
  guaranteed by the protocol. Other properties, such as resistance or detection against packet
  reordering, dropping and replaying, are also taken into account.

  In all communications, confidentiality, integrity and authentication are assured by the use of a
  key only known to the sender and receiver (e.g., a device and the sink); authentication is only
  guaranteed in this case because the key is shared with exactly two parties.
  For simplicity's sake, one key is used for both encryption and integrity, but it would be trivial
  to extend the protocol to use two separate keys for each of those by deriving them from the shared key.

  In the initial key establishment, the use of nonces and the public key of the sink ensures that
  only the sink can decrypt the key, and authenticates the sink in the eyes of the IoT device.
  Assuming the server rejects duplicate pairings, the protocol is also resistant to replay attacks.
  Unfortunately, it is not possible to prevent packet dropping/reordering, but one of the parties will be
  aware that they did not receive the expected response.
  As mentioned in the answer to the previous question, this protocol allows an attacker to pair any device
  they wish, due to the lack of authentication of the IoT device, and therefore the sink should have some
  kind of manual confirmation after pairing a new device.

  As for sensors sending messages to the sink, the use of a sequence number (which can also be considered
  a logic clock) allows the server to detect any reordering, dropping or replaying of a measurement,
  since it is expecting a certain value for this sequence number. It can, therefore, discard any received
  measurements with a sequence number lower than expected. Handling missing skipped numbers in the sequence
  is out of the scope of this question, but a simple action would be to notify the system administrator.

  Similarly, the use of a logic clock in the message sent to the controller allows it to ignore replayed
  or reordered messages, i.e., messages where the logic clock value is lesser than or equal to the
  current logic clock.

  Finally, the use of both periodic key refreshing and _en route_ re-encryption strengthens the
  protocol in the unfortunate case that the attacker is able to get ahold of the key, by
  rotating the key used and using multiple keys, respectively. The new key sent in the key
  refreshing message is encrypted using the sink's public key, so an attacker cannot
  compromise previous or subsequent sessions even if they crack the current device key. This key refreshing
  message cannot be replayed, since the server would already have the new key and discard
  the (now invalid) message.
