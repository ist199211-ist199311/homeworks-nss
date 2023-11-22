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


= Distributed Denial of Service

= Firewalls

= Password Management

= Byzantine Link

= RPKI and ROA
