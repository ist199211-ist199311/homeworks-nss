#import "common/template.typ": cover_page, header, footer, setup_page

#cover_page(title: "Homework 1", date: "November 2023")

#pagebreak()

#show: setup_page

#set page("a4", header: header(title: "HW1"), footer: footer)
#counter(page).update(1)

#outline()
#pagebreak()

= Key Exchange

= Eavesdropping

I'm a bit lost, but I think what the exercise is asking is to calculate the rate
of both A -> B and A -> E and then figuring out what percentage of a message can
E get in the same timespan.

Considering the worst case, that is $d(A,E) = 1.5 d(A,B)$,

+ $ R(A,B) = 1/(d^2(A,B)) $
  $ R(A,E) = 1/(d^2(A,E)) = 1/(1.5^2 dot d^2(A,B))$
  $ R_s (A,B) = 1/(d^2(A,B)) dot (1 - 1/1.5^2) $
  $ R_s (A,B) / R(A,B) = (1-1/1.5^2) = 0.55555(6)$

  55.56% ?

+ Idk, 55.56% again? I'm so lost

+ #set enum(numbering: "a)")
  + 4 hops: $(1000"ms") / (250"ms") = 4$

    In each hop, $7/3$ chance of picking channel without eavesdropper (since they
    are fixed).

    Therefore, chance that neither of the hops picks channel with eavesdropper is $(7/3)^4 = 0.2401$.

    TODO: should we do something with the 55.56% from before here?

  + #let p = 0.5556
    2 hops: $(500"ms") / (250"ms") = 2$
    I'm so confused, but this kinda checks out as 1 unjammed + 1 jammed with 55.56%.

    $ p = binom(2, 1) dot 7/10 dot (1-7/10) = 0.43 $

= Distributed Denial of Service

= Firewalls

= Password Management

= Byzantine Link

= RPKI and ROA
