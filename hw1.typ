#import "@preview/tablex:0.0.6": tablex, hlinex, colspanx
#import "common/template.typ": cover_page, header, footer, setup_page

#cover_page(title: "Homework 1", date: "November 2023")

#pagebreak()

#show: setup_page

#set page("a4", header: header(title: "HW1"), footer: footer)
#counter(page).update(1)

#outline()
#pagebreak()

= Key Exchange

#set enum(numbering: "a)")

+ Two possible attacks would be the following:

  #set enum(numbering: "(i)")

  + The ticket ${A, K_"AB"}_(K_"BS")$ provided by $S$ to $B$ does not include any nonces, compromising its freshness, so an attacker that cracks a previous session key $K_"AB"$ can use it to encrypt  $N_B$ and then forge a message

    $ T -> B: quad {A, K_"AB"}_(K_"BS"), space.quarter {N_B}_(K_"AB") $

    which makes use of a replay attack to re-use the old session's ticket that had been encrypted with the $K_"BS"$ key unknown to the attacker. This message would trick $B$ into believing they were communicating with $A$, as they trust $S$ for authentication. The attacker $T$ could then continue impersonating $A$ using the previous, compromised $K_"AB"$.

  + Given that nonces are 32 bits in length and keys 64 bits, two nonces concatenated together might be misinterpreted as a key, since

    $ underbrace("len"(N_A||N_B), 32 + 32) = underbrace("len"(K_"AB"), 64) $

    As both $N_A$ and $N_B$ are public values, the attacker can compute ${N_B}_(N_A||N_B)$, eavesdrop on message 2 of the protocol to obtain ${A, N_A || N_B}_(K_"BS")$, and use both to forge a message

    $ T -> B: quad {A, N_A || N_B}_(K_"BS"), space.quarter {N_B}_(N_A||N_B) $

    which could be interpreted by $B$ to mean

    $ T -> B: quad {A, K'_"AB"}_(K_"BS"), space.quarter {N_B}_(K'_"AB") $

    where $K'_"AB" = N_A || N_B$. This would again trick $B$ into believing they were communicating with $A$ (authenticated by $S$, who $B$ trusts). The attacker $T$ could then continue impersonating $A$ using the session key $K'_"AB"$.

    This attack assumes, of course, that no field separators of any kind are used, with adjacent values simply being concatenated together - i.e., ${alpha, beta} = {alpha || beta}$.

+ Possible countermeasures to the attacks above would be:

  #set enum(numbering: "(i)")

  + In order to guarantee ticket _freshness_, the nonces should be included in the ticket, allowing $B$ to verify that it is only used once. This could mean, for example, changing messages 3 and 4 of the protocol to:

    $ &3. space.quarter S -> A: quad {B, K_"AB", N_A, N_B}_(K_"AS"), space.quarter {A, K_"AB", bold(N_A\, N_B)}_(K_"BS") \
    &4. space.quarter A -> B: quad {A, K_"AB", bold(N_A\, N_B)}_(K_"BS"), space.quarter {N_B}_(K_"AB") $

    This would no longer allow the described attack to succeed, as each ticket will only be accepted by $B$ once, and the attacker cannot compute a new one (even for a compromised session key) without knowing $K_"BS"$.

    Although in theory only $N_B$ would be necessary, it might be worth it to include $N_A$ as well (per above) in order to halve the probability of nonce collisions that could be exploited by the attacker with a replay attack.

    This countermeasure could also be considered to render unnecessary sending ${N_B}_(K_"AB")$ in message 4, as the ticket is already scoped to $N_B$ and only $A$ would have $K_"AB"$ to encrypt and decrypt subsequent communications, but requiring $A$ to send ${N_B}_(K_"AB")$ simultaneously with the ticket prevents $B$ from falsely believing they have established a valid session with an attacker that could forward the ticket faster than $A$ but did not have $K_"AB"$ to actually communicate any further. If done repeatedly, and if for example $B$ allocated memory for each open session (by remembering, at the very least, $K_"AB"$), an attacker could potentially perform these steps repeatedly as part of a Denial of Service attack.

  + One way to solve this problem would be to promote _explicitness_ by specifying intent, in order to avoid any possible misinterpretations. For example, messages 3 and 4 of the protocol could be changed to:

    $ &3. space.quarter S -> A: quad {B, K_"AB", N_A, N_B}_(K_"AS"), space.quarter {bold("\"Ticket\""), A, K_"AB"}_(K_"BS") \
    &4. space.quarter A -> B: quad {bold("\"Ticket\""), A, K_"AB"}_(K_"BS"), space.quarter {N_B}_(K_"AB") $

    Changing the ticket to explicitly state it consists of a ticket prevents it from having a structure too similar to other messages or message components, regardless of the serialization implementation.

    Finally, one should note that the countermeasure presented for attack (i) would also prevent this attack, since the length coincidence preconditions would no longer be true.

#pagebreak()

= Eavesdropping

#set enum(numbering: "1)")

+ Considering the worst case scenario of $d(A, E) = 1.5 dot.c d(A, B)$, we can use the provided formula to calculate the secure rate between $A$ and $B$:

  $ R_s (A, B) =& R(A, B) - R(A, E) \
  =& k/(d^2 (A, B)) - k/(d^2 (A, E)) \
  =& k/(d^2 (A, B)) - k/(1.5^2 dot.c d^2 (A, B)) \
  =& k/(d^2 (A, B)) (1 - 1/(1.5^2)) \
  =& 5/9 dot.c k/(d^2 (A, B)) $

  where $k$ is some propportionality constant. We can then use that result to calculate the percentage of the transmission that can be communicated confidentially:

  $ (R_s (A, B))/(R(A, B)) = (5/9 dot.c cancel(k/(d^2 (A, B))))/cancel(k/(d^2 (A, B))) = 5/9 approx 55.56% $

+ Using the percentage calculated in the previous question, we can determine the probability of transmitting data confidentially, on average, if we analyze the behavior over an arbitrarily large number of transmissions:

  $ P = lim_(n -> +oo) (5/9 dot.c cancel(n))/cancel(n) = 5/9 $

  where $5/9 dot.c n$ is the percentage of $n$ transmissions that can be communicated confidentially.

+ #set enum(numbering: "a)")

  + With channel hopping every 250ms, a transmission that spans 1 second will last $(1000"ms")/(250"ms") = 4$ slots. We can therefore calculate the probability of such a transmission being completely confidential as:

    $ P = sum_(i=0)^4 binom(4, i) (7/10)^i (3/10 dot.c 5/9)^(4-i) approx 56.4% $

    where, with $i = 0..4$ channels being free from any eavesdroppers, for the 4 slots:

    - $binom(4, i)$ represents choosing which $i$ channels are free;

    - $(7/10)^i$ is the probability of choosing $i$ free channels $(7 = 10 - 3)$; and

    - $(3/10 dot.c 5/9)^(4-i)$ is the probability of choosing $4-i$ eavesdropped channels $(3/10)$ and of communicating confidentially in each of them $(5/9)$ --- here, it is assumed that the circunstances of the previous questions still apply, with $A$ and $B$ still using (only) the proper physical-layer secure coding technique to transmit the data.

    #v(1fr) // force page break, for style (next item would not fully fit)

  + A transmission spanning 0.5 seconds will last $(500"ms")/(250"ms") = 2$ slots. For at least $78%$ to be confidential, there are 2 possible cases:

    - either both channels chosen (for each of the 2 slots) are free and not being eavesdropped --- in this case, $100% >= 78%$ is transmitted confidentially; or
    - one of the channels selected (for either of the 2 slots) is free, but the other is being eavesdropped --- in this case, $1/2 dot.c (100% + 5/9) = 7/9 approx 78%$ is transmitted confidentially.

    We can therefore calculate the probabily with:

    $ P = 1 - (3/10)^2 = 91% $

    where $(3/10)^2$ is the probability of choosing an eavesdropped channel, twice (which is the only case that would lead to less than $78%$ of the transmission being confidential, as $1/2 dot.c (5/9 + 5/9) = 5/9 approx 55.56% < 78%$).

#pagebreak()

= Distributed Denial of Service

#set enum(numbering: "1)")

+ Assuming that the first (all-zeroes host ID) and last (all-ones host ID) addresses of each network cannot be hosts due to representing the network and broadcast (respectively), we have, for each network:

  #let net_sizes = (28, 25, 23, 27)
  #let host_counts = ()

  #for (i, size) in net_sizes.enumerate(start: 1) [
    #host_counts.push(calc.pow(2, 32 - size) - 2)
    - Network \##i: $2^(32 - #size) - 2 = #(host_counts.last())$ hosts
  ]

  #let total_hosts = host_counts.sum()
  In total, this means #total_hosts hosts can participate in the attack.

+ #let host_uplink = 2 // Mbit/s
  #let total_uplink = host_uplink * total_hosts

  With each host having #host_uplink Mbit/s of bandwith, and considering #total_hosts hosts, in aggregate they can generate a total bandwidth of $#host_uplink dot.c #total_hosts = #total_uplink "Mbit/s"$.

+ #let server_downlink = 2000 // Mbit/s

  At the peak of the attack,

  $ (#total_uplink "Mbit/s")/(#server_downlink "Mbit/s") = #(100*total_uplink/server_downlink)% $

  of the webserver's link is used.

+ #let syn_size = 60 // Bytes
  #let host_syn_rate = calc.floor(host_uplink*1e6/(syn_size*8))

  Each host can generate

  $ floor((#host_uplink "Mbit/s")/(#syn_size "Bytes")) = floor((#(host_uplink*1e6) "bits")/(#syn_size dot.c 8 "bits")) = #host_syn_rate "SYN/s" $

  This means that each network can generate

  #for (i, count) in host_counts.enumerate(start: 1) [
    - Network \##i: $#count "hosts" times #host_syn_rate "SYN/s" = #(count * host_syn_rate) "SYN/s"$
  ]

+ #let server_mem = 8 // GBytes (metric)
  #let server_connection_alloc = 256 // Bytes
  #let max_syn_segs = server_mem * 1e9 / server_connection_alloc

  Assuming that each SYN segment received causes the webserver to allocate #server_connection_alloc Bytes, the number of segments required to fill up the web server's available memory is:

  $ (#server_mem "GBytes")/(#server_connection_alloc "Bytes") = (#server_mem times 10^9)/#server_connection_alloc = #max_syn_segs "segments" $

+ #let host_clog_time = calc.round(max_syn_segs / host_syn_rate)

  One host can clog the webserver's memory within

  $ (#max_syn_segs "SYN")/(#host_syn_rate "SYN/s") approx #host_clog_time "s" $

+ Using the previous question's result, each network can clog the webserver's memory within

  #let net_clog_times = ()
  #for (i, count) in host_counts.enumerate(start: 1) [
    #net_clog_times.push(calc.round(host_clog_time/count))
    - Network \##i: $(#host_clog_time "s")/(#count "hosts") approx #net_clog_times.last() "s" $

  ]

+ #let total_clog_time = calc.round(host_clog_time/total_hosts)

  All the networks together can clog the webserver in

  $ (#host_clog_time "s")/(#total_hosts "hosts") approx #total_clog_time "s" $

+ #let ids_detection_percentage = 0.3 // 0..1
  #let ids_detection_time = ids_detection_percentage * total_clog_time

  The attack would be detected by the IDS in $#(ids_detection_percentage*100)% dot.c #total_clog_time "s" approx #ids_detection_time "s"$.

+ In order to prevent against SYN flooding attacks, there are several measures that can be taken, such as:

  - Using SYN cookies, preventing the server from allocating memory when receiving an initial SYN segment, only doing so after receiving the client's second message (this is also effective against origin spoofing, as the client will only be able to send a second message if they receive the server's response);
  - Blocking TCP traffic and using SCTP _(Stream Control Transmission Protocol)_ instead, as it natively supports 4-way handshakes with cookies;
  - Installing an Intrusion Prevention System (IPS) that has a certain probability of detecting SYN flooding attacks and dynamically adjusting firewall rules in order to block that traffic; and
  - Mediating all connections with a proxy or load balancing server that is dedicated to bearing this load and delegating jobs to the actual web server(s).

#pagebreak()

= Firewalls

#set enum(numbering: "1)")

+ #let requirement = counter("requirement")
  #let req() = {
    requirement.step()
    requirement.display("(a)")
  }
  #let rule = counter("rule")
  #let r() = {
    rule.step()
    rule.display()
  }

  Such stateful firewall rules could be:

  #align(center)[
    #tablex(
      columns: (auto,) * 9,
      align: center + horizon,
      [*\#*], [*Direction*], [*Source*], [*Destination*], [*Protocol*], [*Src. Port*], [*Dest. Port*], [*State*], [*Action*],
      hlinex(stroke: 2pt),

      colspanx(9)[_Requirement #req()_],
      [#r() <udp-vpn-in>], [IN], [#sym.star], [17.0.0.0/24], [UDP], [#sym.star], [1194], [N / E], [ACCEPT],
      [#r() <udp-vpn-out>], [OUT], [17.0.0.0/24], [#sym.star], [UDP], [1194], [#sym.star], [EST.], [ACCEPT],
      [#r() <udp-drop-in>], [IN], [#sym.star], [17.0.0.0/24], [UDP], [#sym.star], [#sym.star], [N / E], [DROP],
      [#r() <udp-drop-out>], [OUT], [17.0.0.0/24], [#sym.star], [UDP], [#sym.star], [#sym.star], [N / E], [DROP],

      colspanx(9)[_Requirement #req()_],
      [#r() <attacker-in>], [IN], [203.0.113.0/24], [17.0.0.0/24], [#sym.star], [#sym.star], [#sym.star], [N / E], [DROP],
      [#r() <attacker-out>], [OUT], [17.0.0.0/24], [203.0.113.0/24], [#sym.star], [#sym.star], [#sym.star], [N / E], [DROP],

      colspanx(9)[_Requirement #req()_],
      [#r() <ftp-plain-out>], [OUT], [17.0.0.0/24], [18.0.0.2], [TCP], [#sym.star], [20, 21], [N / E], [REJECT],
      [#r() <ftp-secure-out>], [OUT], [17.0.0.0/24], [18.0.0.2], [TCP], [#sym.star], [22], [N / E], [ACCEPT],
      [#r() <ftp-secure-in>], [IN], [18.0.0.2], [17.0.0.0/24], [TCP], [22], [#sym.star], [EST.], [ACCEPT],

      colspanx(9)[_Requirement #req()_],
      [#r() <ssh-in>], [IN], [198.51.100.0/24], [17.0.0.0/24], [TCP], [#sym.star], [22], [NEW], [ACCEPT],
      [#r() <ssh-out>], [OUT], [17.0.0.0/24], [192.51.100.0/24], [TCP], [22], [#sym.star], [EST.], [ACCEPT],

      colspanx(9)[_Requirement #req()_],
      [#r() <icmp-out>], [OUT], [17.0.0.0/24], [#sym.star], [ICMP], [---], [---], [NEW], [ACCEPT],
      [#r() <icmp-est-in>], [IN], [#sym.star], [17.0.0.0/24], [ICMP], [---], [---], [EST.], [ACCEPT],
      [#r() <icmp-new-in>], [IN], [#sym.star], [17.0.0.0/24], [ICMP], [---], [---], [NEW], [DROP],

      colspanx(9)[_Requirement #req()_],
      [#r() <dns-out>], [OUT], [17.0.0.0/24], [#sym.star], [UDP, TCP], [#sym.star], [53], [N / E], [ACCEPT],
      [#r() <dns-in>], [IN], [#sym.star], [17.0.0.0/24], [UDP, TCP], [53], [#sym.star], [EST.], [ACCEPT],

      colspanx(9)[_Requirement #req()_],
      [#r() <other-in> ], [IN], [#sym.star], [17.0.0.0/24], [#sym.star], [#sym.star], [#sym.star], [N / E], [DROP],
      [#r() <other-out> ], [OUT], [17.0.0.0/24], [#sym.star], [#sym.star], [#sym.star], [#sym.star], [N / E], [DROP],
    )
  ]

  where "N / E" denotes "NEW / ESTABLISHED", and "EST." only the latter connection state.

+ #let rnum(target) = "#" + locate(loc => rule.at(query(target, loc).first().location()).first() + 1)
  #let rnums(..targets) = targets.pos().map(rnum).join(", ")

  In order to fulfill all the requirements, a possible rule ordering could be, for each default policy:

  - *DROP-ALL:* #rnums(<attacker-in>, <attacker-out>, <udp-vpn-in>, <udp-vpn-out>, <ftp-plain-out>, <ftp-secure-out>, <ftp-secure-in>, <ssh-in>, <ssh-out>, <icmp-out>, <icmp-est-in>, <dns-out>, <dns-in>).
  - *ACCEPT-ALL:* #rnums(<attacker-in>, <attacker-out>, <udp-vpn-in>, <udp-vpn-out>, <ftp-plain-out>, <ftp-secure-out>, <ftp-secure-in>, <ssh-in>, <ssh-out>, <icmp-out>, <icmp-est-in>, <dns-out>, <dns-in>, <other-in>, <other-out>).

  #v(1fr) // force page break, for style (next item would not fully fit)

+ The two default policies work in opposite fashion and can be considered to be more appropriate for different contexts. Example use cases could be:

  #set enum(numbering: "(i)")
  - *DROP-ALL:*
    + A sensitive network that must be as isolated as possible, with any potentially permitted traffic pattern having to be identified, analyzed, vetted, and approved for security purposes
    + An environment pertaining to a highly-regulated economic sector, where certain requirements (such as forbidding any outbound traffic flows, for data protection reasons) are paramount and must be easily audited by government authorities
  - *ACCEPT-ALL:*
    + A server that frequently launches services on different ports, with a dynamicity that makes it harder to constantly adjust firewall rules to allow traffic to and from those services (or if doing so would introduce too much overhead)
    + A development environment where flexibility and ease of service/configuration deployment take precedence over strict, in-depth access control (especially if it is already part of a larger, stricter network that safeguards it from most external interference)

  It is also worth noting that it is trivial to emulate the opposite policy when using a given default policy, by simply appending the chain with a rule ACCEPT'ing or DROPP'ing all traffic (respectively for DROP-ALL and ACCEPT-ALL).

#pagebreak()

= Password Management

#set enum(numbering: "a)")

+ If the alphabet being considered is the same, then yes: $N = \# Sigma$ is constant, therefore so will $log_2 N$ be, and thus $H = L dot.c log_2 N prop L$.

  Otherwise, if the alphabet is different, no conclusions can be inferred. For example, if $N_1 = \# Sigma_1 = 4$, $L_1 = 10$, $N_2 = \# Sigma_2 = 64$, $L_2 = 4$, we have $L_1 > L_2$, but

  #set math.cases(reverse: true)
  $ cases(H_1 &= L_1 dot.c log_2 N_1 &= 10 dot.c log_2 4 &= 20 "bits", H_2 &= L_2 dot.c log_2 N_2 &= 4 dot.c log_2 64 &= 24 "bits") ==> H_1 < H_2 $

  This can have subtle implications, as several different alphabets may be at play, and the password's entropy (as a measure of unpredictability) would then be the minimum of all those partial entropy values (each with regard to a different alphabet). For instance, although `qwerty` has the same length as `mqprhx` and so would have the same entropy value with respect to an alphabet such as the set of all ASCII lowercase letters, `qwerty` is much more likely to be susceptible to a dictionary attack, wherein $L_D = 1$ and $N_D$ would be the dictionary's length (which could be quite small and still include this word, if per usual it contained the most common passwords), leading to a much smaller $H = H_D$.

+ #set enum(numbering: "(i)")

  + 16 symbols: $H = 16 dot.c log_2 256 = 128 "bits"$
  + 20 symbols: $H = 20 dot.c log_2 256 = 160 "bits"$
  + #set math.cases(reverse: true)
    $ cases("Naïvely," &H_N &= 10 dot.c log_2 256 &= 80 "bits", "Using dictionary," &H_D &= 1 dot.c log_2 2000 &approx 11 "bits") ==> H = min{H_N, H_D} approx 11 "bits" $

+ KDFs _(Key Derivation Functions)_ are used to derive cryptographic keys from a secret.

  The primary purpose of having several hash iterations in KDFs is to make it slower for attackers to brute-force cracking the secret key by trying different possible secret combinations and checking whether the final keys match the expected value. If the function has more hash iterations, it becomes slower to compute, therefore potentially making it infeasible for attackers to try many combinations. This does not change the asymptotic time complexity associated with the attack, but it does introduce a large constant that can nonetheless have severe practical consequences for the attack's feasibility.

  From a security standpoint, more iterations make the KDF slower and are therefore better (magnifying the effect described above), but there is a trade-off to be considered with _usability_: if the KDF is _too_ slow, it may prove to be a limitation to legitimate users and impact normal system usage. In summary, more iterations are better but only up to a certain point, after which the impact on user experience is non-negligible.

+ Considering peppers as described in the question, and assuming (per its wording) that they are kept by the user but generated by the server (per-user, perhaps pseudo-randomly):

  - Advantage: if the system (including the authentication database) is fully compromised, the pepper is not stored anywhere, so attackers still need to bruteforce each user's pepper, which may be computationally infeasible (especially when paired with a slow hash function)
  - Disadvantage: there can be usability concerns with regards to requiring users to store their pepper value and submitting it on every login request, which can be a burden if the pepper is sufficiently long

  #v(1fr) // force page break, for style (next item would not fully fit)

+ We can quantify password cracking difficulty using entropy:

  - *64-bit salt:* since the salt value is known, using it is trivial if the scheme is public, and only ensures the calculation happens in the first place rather than using rainbow tables with pre-cracked hashes. This means that the entropy will be the same as the password's own entropy:

  $ H = log_2 1 + H_P = 0 + H_P = 10 "bits" $

  - *64-bit pepper:* we now need to consider the unpredictability associated with the need for bruteforcing each of the 64 bits in the pepper:

  $ H = 64 dot.c log_2 2 + H_P = 64 + 10 = 74 "bits" $

+ In terms of unpredictability,

  $ H_P &= 32 dot.c log_2 16 &= 128 "bits" \
  H_F &= 128 dot.c log_2 2 &= 128 "bits" $

  the entropy is the same, so in theory it does not matter which of them is used. The original password should therefore be preferred, in order to avoid unnecessary calculations associated with the KDF.

  However, this is no longer the case if other factors are present, such as if the KDF is not deterministic (based exclusively on the secret input) and generates a session-specific key, in which case the KDF output should be used to promote forward secrecy across sessions, assuming that the KDF is one-way.

#pagebreak()

= Byzantine Link

#set enum(numbering: "1)")

+ Communicating exclusively in-band through LSAs _(Link State Advertisements)_, it is not possible for $G$ and $E$ to introduce a fake link among themselves, as the advertisement would have to necessarily pass by one or more other routers, who would discard it. For example, if $G$ generated and signed an advertisement $AA = {"'I am G'", "'Next hop is E'"}_("Priv"_G)$ and then sent it to $E$ through $F$, the latter would realize that $AA$ is invalid (the next hop field should be $F$, not $E$) and would drop it.

  Conversely, if $G$ and $E$ can communicate out-of-band, it is possible for them to pretend a fake link exists between them. For example, $G$ can generate $AA = {"'I am G'", "'Next hop is E'"}_("Priv"_G)$ as before, but now send it encoded as a regular data message addressed to $E$ (rather than announcing it as a control LSA to $F$). As $AA$ would now be disguised as a regular, inconspicuous data stream, any intermediary routers would be oblivious to it representing an LSA and would not validate it, simply forwarding it to $E$. On arrival, $E$ could then generate $AA' = {AA, "'I am E'", "'Next hop is F'"}_("Priv"_E)$ and only now advertise $AA'$ as an LSA that would necessarily be considered valid by other routers. Using this technique, $G$ and $E$ would be able to trick others into believing a link exists between them.

  Evidently, this could also be simplified if both routers had each other's private keys and could sign initial advertisements on behalf of each other, therefore being able to forge valid LSAs claiming a link exists between them.

+ As asymmetric cryptography primitives can be computationally intensive and introduce undesired overhead to every announcement hop, it would be beneficial to reduce this cost, while maintaining the desirable properties of authenticated announcements. One solution would be to use the protocol described in Papadimitratos & Haas (2002)#footnote[P. Papadimitratos and Z. J. Haas, "Securing the Internet routing infrastructure," in IEEE Communications Magazine, vol. 40, no. 10, pp. 60-68, Oct. 2002, doi: 10.1109/MCOM.2002.1039858.]:

  - Each router $R$ sends their initial LSA as normal, with the exception that for each link $j$ it chooses a random value $N_(R,j)$ and includes $H^n (N_(R,j))$ in that initial LSA (which is authenticated with $R$'s private key and can be verified to be so by a receiving router $S$) --- here, $H^n (x) = H(H(...(H(x))))$ represents computing $n$ successive iterations of a hash function $H$, for some large $n$
  - For each subsequent LSA transmitted by $R$, instead of signing it with its private key (which would be computationally expensive), it simply attaches to the LSA the next value in the hash chain, i.e., $H^(n-p) (N_(R,j))$, where $p$ is a counter between $0$ and $n$ of how many LSAs (including the initial one) have been sent by $R$ --- this means that each value $H^(n-p) (H_(R,j))$ is only sent once, as $p$ increases immediately afterwards
  - When another router $S$ receives an LSA from $R$ that is not signed with the latter's private key but rather has some hash value $HH$, $S$ can verify the LSA was legitimately sent by $R$ by checking whether $H(HH) = HH'$, where $HH'$ is the previous hash value received from $R$ (in the previous authenticated LSA) --- since $H$ is one-way, only $R$ (that has the original secret) can generate $HH$ such that $H(HH) = HH'$. $S$ then stores $HH$ as the new value for $HH'$, so that it can verify the next LSA in the same fashion
  - When $p = n$, $R$ chooses a new $N'_(R,j)$ and sends another LSA authenticated with its private key, including $H^n (N'_(R,j))$ and re-starting the hash chain from another secret

  This protocol has the advantage of only requiring asymmetric cryptography computations every $n$ LSAs sent, greatly reducing the overhead associated with advertisement security. It also centralizes most of the computational burden on just one node (the LSA sender), as all others only need to compute one hash iteration (though the sender must compute $n-p$).

+ Yes, if $A$ and $D$ wish to communicate with each other, the shortest real path $A - H - C - D$ has cost $2 + 4 + 3 = 9$, but if $G$ and $E$ advertise a fake link between them with cost $alpha <= 4$, the path $A - G - E - D$ with cost $3 + alpha + 1 <= 8 < 9$ would become the shortest, therefore tricking $A$ and $D$ into communicating through the malicious routers and attracting traffic.

+ In order for $G$ and $E$ to control all communications between $A$ and $D$ regardless of what cost is advertised for the $G-E$ fake link (allowing it even to be arbitrarily large, $alpha >> 4$), they could recruit router $C$ to also become malicious. As all traffic passes through $C$ (except for that which already passes through $G$ and/or $E$), if that router can be controlled by a malicious actor, it could advertise all its paths as costing a very high value (or not advertise them at all), leading $A$ and $D$ to always choosing to route through $G$/$E$. $D$ would receive $C$'s new advertisement (either inflated or non-existent) directly, and $A$ would indirectly feel its consequences through the information propagated by $B$ and $H$.

#pagebreak()

= RPKI and ROA

#set enum(numbering: "1)")

+ Considering the following language and procedures from the Internet Engineering Task Force:

  #block(stroke: (left: 2pt + rgb("#888")), quote(block: true, attribution: [RFC6811])[
      - (...)
      - Covered: A Route Prefix is said to be Covered by a VRP when the VRP prefix length is less than or equal to the Route prefix length, and the VRP prefix address and the Route prefix address are identical for all bits specified by the VRP prefix length. (That is, the Route prefix is either identical to the VRP prefix or more specific than the VRP prefix.)
      - Matched: A Route Prefix is said to be Matched by a VRP when the Route Prefix is Covered by that VRP, the Route prefix length is less than or equal to the VRP maximum length, and the Route Origin ASN is equal to the VRP ASN.

    Given these definitions, any given BGP Route will be found to have one of the following validation states:
      - NotFound: No VRP Covers the Route Prefix.
      - Valid: At least one VRP Matches the Route Prefix.
      - Invalid: At least one VRP Covers the Route Prefix, but no VRP Matches it.
  ])

  For each announcement:

  #set enum(numbering: "(1):")

  + `130.0.0.0/16`, originally announced by `AS234` (`/16` means a netmask of `255.255.0.0`)

    - `130.0.0.0/16` is not compatible with any known VRP, so no VRP Covers the announcement
    - Conclusion: #underline([_unknown_])

  + `140.0.0.0/8`, originally announced by `AS213` (`/8` means a netmask of `255.0.0.0`)

    - VPR \#2 Covers the announcement, as $8_"(VRP.length)" <= 16_"(announcement)"$ and the first 8 bits of `140.0.0.0` (VRP) and `140.0.0.0` (announcement) are identical
    - VRP \#2 Matches the announcement, as it Covers it, $16_"(announcement)" <= 16_"(VRP.maxlength)"$, and the announcement's origin ASN (`AS213`) is equal to the VRP's ASN (`AS213`)
    - Conclusion: #underline([_valid_]) (at least one VRP Matches the announcement)

  + `130.237.0.0/16`, originally announced by `AS213` (`/16` means a netmask of `255.255.0.0`)

    - VRP \#1 Covers the announcement, as $16_"(VRP.length)" <= 16_"(announcement)"$ and the first 16 bits of `130.237.0.0` (VRP) and `130.237.0.0` (announcement) are identical
    - VRP \#1 does not Match the announcement, as the latter's origin ASN (`AS213`) is not equal to the VRP's ASN (`AS234`)
    - No other VRPs Cover the announcement, as `130.237.0.0/16` is not compatible with the only other one
    - Conclusion: #underline([_invalid_]) (at least one VRP Covers the announcement, but none Match it)

  + `140.248.0.0/16`, originally announced by `AS213` (`/16` means a netmask of `255.255.0.0`)

    - VPR \#2 Covers the announcement, as $8_"(VRP.length)" <= 16_"(announcement)"$ and the first 8 bits of `140.0.0.0` (VRP) and `140.248.0.0` (announcement) are identical
    - VRP \#2 Matches the announcement, as it Covers it, $16_"(announcement)" <= 16_"(VRP.maxlength)"$, and the announcement's origin ASN (`AS213`) is equal to the VRP's ASN (`AS213`)
    - Conclusion: #underline([_valid_]) (at least one VRP Matches the announcement)

    #v(1fr) // force page break, for style (next item would not fully fit)

  + `130.237.1.0/24`, originally announced by `AS234` (`/24` means a netmask of `255.255.255.0`)

    - VRP \#1 Covers the announcement, as $16_"(VRP.length)" <= 24_"(announcement)"$ and the first 16 bits of `130.237.0.0` (VRP) and `130.237.1.0` (announcement) are identical
    - VPR \#1 does not Match the announcement, as $24_"(announcement)" lt.eq.not 16_"(VRP.maxlength)"$
    - No other VRPs Cover the announcement, as `130.237.1.0/24` is not compatible with the only other one
    - Conclusion: #underline([_invalid_]) (at least one VRP Covers the announcement, but none Match it)

+ #set enum(numbering: "1)")

  + Yes, VRP \#2 is susceptible to a forged-origin sub-prefix hijack, as it makes use of the maxlength property. Announcement \#4 could be an example of such an attack, with `AS431` forging an announcement (which, as described in the previous question, would be accepted as valid) as if it had originated from `AS213`, who is authorized to issue it.

    If `AS213` does not make any analogous announcement, perhaps because it only uses (and announces) another subnet such as `140.100.0.0/16`, the attacker could announce `140.248.0.0/16` and be uncontested (this would be the only route for that subnet, as no other would be announced by the real AS), effectively giving them control over the subnet.

    Even with `AS213` announcing `140.0.0.0/8`, the attacker's `140.248.0.0/16` announcement would still prevail as it is more specific than the former, and routers will choose the route with the longest prefix.

  + Yes, the solution would be the only use minimal ROAs - that is, only issue ROAs for exactly the routes that will be announced, rather than relying on the maxlength attribute for the flexibility it offers (which comes as a trade-off for security). In this case, the following two ROAs could be used:

    $ &("AS213", 140.0.0.0, 8, -) \
    &("AS213", 140.100.0.0, 16, -) $

    This means that an attacker could no longer announce `140.248.0.0/16` (even if allegedly on behalf of `AS213`), as none of the ROAs would Cover it.

    It should be noted, however, that this solution prevents forged-origin *sub-*prefix hijacks, but it does not secure against forged-origin *prefix* hijacks, as an attacker can still forge an announcement such as `(140.0.0.0/8; ASPATH: AS[attacker], AS213)`, which would conflict with the real announcement made by the legitimate `AS213`. These attacks are of a lower severity, however, as then the attacker would no longer be presenting the _only_ route to `AS213`, just an additional one that would attract less traffic (especially since the fake announcement would always be one hop longer than the legitimate announcements coming directly from `AS213`).

+ With a global view of the network topology, we can consider and validate the `ASPATH` attribute in each announcement. In this manner, we can determine that announcement \#4 is invalid as there is no path connecting `AS213` to `AS431` directly, so it must have been forged. The remaining announcements are plausible as they refer to existing router paths in accordance with the known network layout.