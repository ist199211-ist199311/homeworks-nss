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

    #v(1fr) // force page break for style; next item wouldn't fit

  + One way to solve this problem would be to promote _explicitness_ by specifying intent, in order to avoid any possible misinterpretations. For example, messages 3 and 4 of the protocol could be changed to:

    $ &3. space.quarter S -> A: quad {B, K_"AB", N_A, N_B}_(K_"AS"), space.quarter {bold("\"Ticket\""), A, K_"AB"}_(K_"BS") \
    &4. space.quarter A -> B: quad {bold("\"Ticket\""), A, K_"AB"}_(K_"BS"), space.quarter {N_B}_(K_"AB") $

    Changing the ticket to explicitly state it consists of a ticket prevents it from having a structure too similar to other messages or message components, regardless of the serialization implementation.

    Finally, one should note that the countermeasure presented for attack (i) would also prevent this attack, since the length coincidence preconditions would no longer be true.

= Eavesdropping

= Distributed Denial of Service

= Firewalls

= Password Management

= Byzantine Link

= RPKI and ROA
