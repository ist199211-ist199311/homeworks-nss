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
  alternatively, for the opposite scenario, one $M_arrow.b$ could accomodate
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

+ TODO

+ TODO

+ TODO

#pagebreak()

= DNS Attack

#set enum(numbering: "1)")

+ TODO

+ TODO

+ TODO

+ TODO

+ TODO

+ TODO

#pagebreak()

= Near Field Communication Attacks

#set enum(numbering: "1)")

+ TODO

+ TODO

+ TODO

#pagebreak()

= IoT

#set enum(numbering: "1)")

+ TODO

+ TODO

+ TODO

+ TODO

+ TODO
