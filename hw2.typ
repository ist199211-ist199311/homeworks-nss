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

  $ R:     & k <- "RNG"() \
  R:     & a <- "Enc"_"Pub"_"C" (k) \
  R:     & b <- E_k (m_1) \
  R -> C:& (N_R, a, b, "HMAC"_k (N_R, a, b)) \
  C:     & c <- E_k (m_2) \
  C -> R:& (N_R, c, "HMAC"_k (N_R, c)) \
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

+ TODO

+ TODO

+ TODO

+ TODO

+ TODO
