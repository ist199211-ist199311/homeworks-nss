#import "@preview/tablex:0.0.6": tablex, hlinex, colspanx
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

#let md5_hashtable = (
  "50d02858": "045afeaef6d4b1b351aa35d50c84d424",
  "045afeaec7e2b366": "a762680130cabd8feb7fc68e50515a61",
  "a762680123f140ad": "1461c8e3718070f827086b6f541131ea",
  "1461c8e395294aec": "9cb546a7ff135ddd4643191c3dbbefc8",
  "9cb546a7a4745acb": "efe5033737345c91f2453871b3a1528b",

  "07fd01d5": "0561a9ca01d3ba79ece8055b0d523147",
  "0561a9ca5a9d0480": "833f717633a2f7bb70c9d95403da966c",
  "833f717693aded1d": "c30c554bb3796b7e7c73906e26086adc",
  "c30c554bd97d3412": "707791877995a6b484fcea53ef21f265",
  "70779187414833e5": "ede9aa5fe7b69e13042ade7190c91136",
)

#let castor_hash(msg) = {
  md5_hashtable.at(msg).slice(0, count: 8)
}

#let castor_solve(H, bk, fk) = {
  [ $ H = #H $ ]
  let last_hash = castor_hash(bk)
  let last_hash_repr = [ $h(b_k)$ ]
  [ $ #last_hash_repr = #last_hash $ ]

  for (i, f) in fk.enumerate(start: 1) {
    last_hash = castor_hash(last_hash + f)
    last_hash_repr = [ $h(#last_hash_repr || x_#i)$ ]
    [ $ #last_hash_repr = #last_hash $ ]
  }

  if last_hash == H {
    [ The packet is forwarded, H matches ]
  } else {
    [ The packet is *NOT* forwarded, H differs ($#last_hash #sym.eq.not #H$) ]
  }
}

+ TODO

  #castor_solve("efe50337", "50d02858", ("c7e2b366", "23f140ad", "95294aec", "a4745acb"))

+ TODO

  #castor_solve("12328e72", "07fd01d5", ("5a9d0480", "93aded1d", "d97d3412", "414833e5"))

#pagebreak()

= Secure Data Forwarding

#set enum(numbering: "a)")

+ TODO

  ?

  F will have to read the full packet if it wants to get some information, but
  since it is end-to-end authenticated and its integrity is validated, it cannot
  change anything without it being detected.

+ TODO

  ?

  Packet dropping may or may not be addressed depending on the protocols being used
  in the upper layers. If A sends a message and expects a response, F will not be able
  to provide that authenticated response, but if A is just sending a message and G
  only has to send an unauthenticated acknowledgement, F can fake that (e.g., TCP ACK).

  In any case, even if A and/or G can know that their packets are being dropped, they
  cannot do anything about it.

  Packet data modification is addressed as its content is authenticated and its integrity
  is validated, but packet metadata in the lower layers might be vulnerable to modifications.

+ TODO

  ?

  Since feedback is now authenticated, F can no longer fake a response back.
  It can still prevent packets from being sent, even if A and/or G are aware
  packets are being dropped.

+ TODO

  If the packet goes to C, it will still go to F.
  If the packet goes to B, however, the shortest path is ABEG, which is not under attack.

  Therefore, 50% of packets will be delivered to G.

+ TODO

  If the packet goes to B, the shortest path is ABEG, which is not under attack.
  If the packet goes to C, it can go either to B (not under attack), E (not under attack)
  or to F (under attack).

  Therefore,

  $ P_"delivered" = 1 - 1/2 dot 1/3 = 5/6 $

+ TODO

  Same as above, except that B can send to C and C to F.

  $ P_"delivered" = 1 - 1/2 dot 1/3 - 1/2 dot 1/3 dot 1/2 = 1 - 1/6 - 1/12 = 3/4 $

+ TODO

  To be certain, either (B and C) or (D and E).

#pagebreak()

= Birthdays

#set enum(numbering: "1)")

+ TODO

  It is the probability phenomena where in a group of 23, there is a probability greater than 50%
  that two people share a birthday. Generically, it is non-intuitively probable that there is a
  collision between two distinct events, where trying to collide with a specific value would be
  way less probable.

+ TODO

  The BIND birthday attack works by sending $N$ requests to the DNS server, while also sending $N$
  spoofed responses to the DNS server.
  There are only $2^16$ possible transaction IDs, so it is more likely that out of those $N$ requests/response pairs,
  one of them matches than that one request is sent and we try to guess which transaction ID it was.

  Taking the analogy of birthdays, it is more likely that, out of two groups of 10 people, there is one pair that
  shares a birthday than (at least) one person having a specific birthday out of a 20 people group.

+ TODO

  Recalling the formula:

  $ P_"collision" = 1 - (1 - 1/t)^((n dot (n-1))/2) $

  Considering that the QID range is $[0; 2^16[$, that is, $2^16$ possible values,
  we want to find $n$ such that:

  $ P_"collision" >= 25 => 1 - (1-1/(2^16))^((n dot (n-1)) /2) >= 25 $

  By plotting the graph of this function and intercepting with $y=0.25$, we find out $n=195$ (since $n$ is an integer).

#pagebreak()

= DNS Attack

#set enum(numbering: "1)")

+ TODO

  They can perform a DoS attack by spoofing the "from address" in the request packet header.
  This way, the DNS server will then send the response to the victim instead of the attacker,
  using up the victim's bandwidth.

+ TODO

  No, DNSSEC only protects the contents of the DNS response.
  Rate limiting? idk

+ TODO

  $ "af" = 1200 / 64 = 18.75 $

  It is important for the attacker that this number is high, so that they can exhaust
  the victim's bandwidth without using much bandwidth themselves.

+ TODO

  No, because the outgoing request from the resolver to the victim can still go through the firewall,
  since new outgoing connections are allowed.

  The private DNS resolver should only listen and reply to addresses in the local network. (?)

+ TODO

  It is possible to prevent these responses from getting through the firewall, but they might still exhaust the link
  until the firewall is reached.

  We can use a firewall with a default DROP policy, and:

  - OUT: NEW, ESTABLISHED
  - IN: ESTABLISHED

  This way, connections that have not been started by a host in the network would not be able
  to get in to the network, no matter the number of attackers.

+ TODO

  Rate limiting (?) idk

#pagebreak()

= Near Field Communication Attacks

#set enum(numbering: "1)")

+ TODO

  IDEA: Share a symmetric key using the certificate.

  Since the card is resource constrained, we want to avoid multiple round trips
  (that would involve keeping state on the card which might not be realistic).

  Assumption: the reader knows the public key of the card.

  $ R: a <- "Enc"_"Pub"_C (K_"CR") $ // is it a problem not sending a hash of this? can't think of a possible attack, the nonce on the next message protects it
  $ R: b <- E_K_"CR" (N_R || m_1) $
  $ R -> C: (a, b, "HMAC"(K_"CR", b)) $
  $ ... $
  $ C: c <- E_K_"CR" (N_R || m_2) $
  $ C -> R: (c, "Sign"_"Priv"_C (H(c))) $
  $ ... $
  $ R: "Estimate RTT and" d(R,C) $

+ TODO

  Assuming the cryptography functions have negligible overhead (i.e. are instantaneous),
  we can still estimate $d(R,C)$ given the RTT.
  If we can't assume negligible overhead for these functions, we might instead assume that
  they take a static amount of time, and therefore only have to subtract that from the RTT.

+ TODO

  ?
  Assuming the second case in the question above, where there is a static processing time
  overhead for the cryptographic functions in the protocol, one possibility would be
  for a replay attack, where the attacker can reply with a previous message and pretend
  to be closer to the reader by avoiding this cryptographic processing time.
  Our protocol, however, already prevents replay attacks by the use of a nonce, so
  this attack is not feasible.
  To further protect, and assuming the card has that capability, we could also
  include the processing time spent on the time in the response, so the reader can
  more accurately determine $d(R, C)$.

#pagebreak()

= IoT

#set enum(numbering: "1)")

+ TODO

  ???
  - $alpha$ Soil moisture sensors
  - $beta$ Climate controllers (nothing is specified about this, so we will assume we
    only need to secure the controller and that the rest of the system is analog, e.g. fans, heaters, etc).
  - $gamma$ Irrigation controllers (again, controller is digital, rest of the system is analog)
  - $delta$ Drones (for simplicity, we will assume they can talk directly to the central server)
  - $epsilon$ RFID readers --- should we include this?
  - $zeta$ RFID tags

  We assume that this is a mesh network, a Wireless Sensor Network as described in the slides,
  and therefore there are no "access points" connecting the devices to the central server (sink).

  NOTE: I'm not sure if we need to list all these devices or just a generic "sensor" and "sink".

+ TODO

  Our protocol is designed to prevent an attacker from reading and/or modifying measurements.
  It should also prevent an attacker from deleting and/or reordering measurements without being detected.

  For systems that need to receive commands (i.e., actions), the protocol must also prevent
  a malicious actor from initiating or altering commands.

  To achieve these goals, we will use symmetric encryption for confidentiality (using, for example, AES
  with CBC cipher mode), and Message Authentication Codes (e.g., HMAC). To ensure measurements
  aren't deleted and/or reordered, we will keep a counter per sensor, which increases with each measurement
  (maybe use timestamps instead? might prevent attacks where the attacker delays packets).

+ TODO

  ??
  Hardware-accelerated AES is fast and does not consume a lot of power, so we can use that (e.g., AES-CBC).
  HMAC with a SHA3-512 hash.

  Interesting source: https://www.ncbi.nlm.nih.gov/pmc/articles/PMC6806263/

+ TODO

  ??

  Note: it is assumed that we have secure path establishment in the network (footnote 1 of module 8 notes).

  - *Initial key establishment ("pairing")*

    It is assumed the IoT devices come preloaded with the sink's certificate (or, alternatively,
    of a CA that signs the sink's certificate -- we'll keep this simple and assume the IoT devices
    know the public key of the sink).

    $S$ for sink, $D_i$ for device

    #let key = $K_(D_i"/"S)$

    $ D_i: "generates random" key $
    $ D_i: a <- "Enc"_"Pub"_S (key, N_D_i) $
    $ D_i -> S: (a, "HMAC"(key, a)) $
    $ S: "validate hmac and stuff" $
    $ S: b <- E_key ("\"key establishment\"", N_D_i, N_A) $
    $ S -> D_i: (b, "HMAC"(key, b)) $
    $ ... "bla bla do something with nonces" $

    I'm not sure this works: an attacker would still be able to enrol any device they want,
    and prevent the legit devices from being paired.
    Should we have private keys on the IoT devices instead, all signed by the some (trusted) CA?

  - *Sensor*

    The sensor would periodically send messages back to the server, using the key it they have
    established, where $"Seq"_D_i$ is the sequence number of the measurement.

    $ D_i: a <- E_key (D_i, "Seq"_D_i, "measurement data") $
    $ D_i -> S: (a, "HMAC"(key, a)) $

  - *Command (actions)*

    The server can also instruct the IoT devices to perform an action (e.g., trigger the irrigation systems):

    $ S: a <- E_key (D_i, t^S_"clock", N_S, "action data") $
    $ S -> D_i: (a, "HMAC"(key_a)) $

  - *Other stuff*

    Should we have periodic key refreshing? What about en route re-encryption? I think we should.

+ TODO

  Note: assume en route re-encryption and key refreshing.

  The encryption and "HMAC" guarantee authentication, confidentiality and integrity of the sensor data (measurements)
  sent by the IoT sensor to the server (sink), as long as the adversary cannot get the key $key$.
  This, of course, cannot be a valid assumption, since these IoT devices might be left unattended, and
  therefore this key might be extracted by the adversary. Two measures are in place to attenuate this
  vulnerability: first, this key is periodically refreshed (disguised as a measurement, for example),
  making it infeasible for an attacker to keep extracting the key. Secondly, we have en route re-encryption,
  which means that, as long as the attacker is more than one hop away from the IoT device, the message
  will be encrypted with the key of another IoT device. To break this encryption, the attacker would need
  the keys of all the IoT devices in the path from the sensor to the server.
