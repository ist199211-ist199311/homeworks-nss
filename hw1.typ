#import "common/template.typ": cover_page, header, footer, setup_page

#cover_page(title: "Homework 1", date: "November 2023")

#pagebreak()

#show: setup_page

#set page("a4", header: header(title: "HW1"), footer: footer)
#counter(page).update(1)

#let rnd2 = calc.round.with(digits: 2)

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

+ TODO: should we consider the first and last hosts of each subnet?

  #let host_count = (16, 128, 512, 32)
  - Network 1: /28 -> #host_count.at(0) hosts
  - Network 2: /25 -> #host_count.at(1) hosts
  - Network 3: /23 -> #host_count.at(2) hosts
  - Network 4: /27 -> #host_count.at(3) hosts

  #let hosts = host_count.sum()
  Therefore, #hosts will be able to participate in the attack.

+ #let host_uplink = 2 // in Mbps
  #let total_uplink = host_uplink * hosts

  We can simply multiply the number of hosts by the uplink of each of them.

  $ #host_uplink "Mbit/s" dot #hosts "hosts" = #total_uplink "Mbit/s"
  = #rnd2(total_uplink / 1000) "Gbit/s"$

+ #let webserver_downlink = 2000 // in Mbps

  Since we know the peak bandwidth from the previous question, we can divide it by
  the total downlink bandwidth of the web server.

  $ (#total_uplink "Mbit/s") / (#webserver_downlink "Mbit/s") =
  #rnd2((total_uplink / webserver_downlink) * 100) % $

+ #let tcp_syn_len = 60 // in bytes
  #let tcp_syn_len_bit = tcp_syn_len * 8 // in bits

  Each SYN packet is $#tcp_syn_len dot 8 = #tcp_syn_len_bit$ bits long.\
  Each host can send up to #host_uplink Mbit/s, therefore,

  #let syn_per_host = (host_uplink * 1000) / tcp_syn_len
  $ (#host_uplink "Mbit/s" dot 1000) / #tcp_syn_len_bit = #rnd2(syn_per_host) "SYN per second" $

  So, per network, considering the number of hosts from question 1,

  #let syn_per_network = host_count.map(c => c * syn_per_host)
  #for (i, c) in host_count.enumerate() [
    - Network #(i + 1): $#c "hosts" dot #rnd2(syn_per_host) "SYN segments/s"
      = #rnd2(syn_per_network.at(i)) "SYN segments/s" $
  ]

+ #let server_memory = 8 // in Gbytes
  #let syn_memory = 256 // in bytes

  We can simply divide the server memory by the memory each connection takes up.

  #let max_syn = (8 * 1000 * 1000) / 256

  $ (#server_memory "Gbytes") / (#syn_memory "bytes") = #max_syn "SYN segments" $

+ For one host:

  $ t = (#max_syn "SYN segments") / (#rnd2(syn_per_host) "SYN segments/s") =
  #rnd2(max_syn / syn_per_host) "s" $

+ For each network:

  #for (i, throughput) in syn_per_network.enumerate() [
    - Network #(i + 1): $ t_N_#(i + 1) = (#max_syn "SYN segments") / (#rnd2(throughput) "SYN segments/s")
      = #rnd2(max_syn / throughput) "s" $
  ]

+ Total SYN segment throughput for all networks together:

  #let syn_total = syn_per_network.sum()
  $ "throughput" = #(syn_per_network.map(t => [#rnd2(t)]).join([#sym.plus])) =
  #rnd2(syn_total) "SYN segments/s" $

  $ t = (#max_syn "SYN segments") / (#rnd2(syn_total) "SYN segments/s") =
  #rnd2(max_syn / syn_total) "s" $

+ #let percent_memory = 0.3
  We can simply do the same, but with #(percent_memory * 100)% of the total RAM:

  #let percent_max_syn = max_syn * percent_memory

  $ (#percent_memory dot #server_memory "Gbytes") / (#syn_memory "bytes") = #percent_max_syn "SYN segments" $

  $ t = (#percent_max_syn "SYN segments") / (#rnd2(syn_total) "SYN segments/s") =
  #rnd2(percent_max_syn / syn_total) "s" $

+ ?

  From slides:
  - Use a proxy in front of the actual server
  - TCP/SYN cookies
  - SCTP Protocol

= Firewalls

+ #table(
    columns: (2fr, 3fr, 6fr, 6fr, 3fr, 3fr, 3fr, 6fr, 4fr),
    inset: 5pt,
    align: horizon,
    [],
    [*Dir*],
    [*Src*],
    [*Dest*],
    [*Protocol*],
    [*Src Port*],
    [*Dest Port*],
    [*State*],
    [*Action*],
    [1, (a)],
    [IN],
    [ANY],
    [ANY],
    [UDP],
    [ANY],
    [1194],
    [NEW, ESTABLISHED],
    [ACCEPT],
    [2, (a)],
    [OUT],
    [ANY],
    [ANY],
    [UDP],
    [1194],
    [ANY],
    [ESTABLISHED],
    [ACCEPT],
    [3, (a)],
    [IN, OUT],
    [ANY],
    [ANY],
    [UDP],
    [ANY],
    [ANY],
    [NEW, ESTABLISHED],
    [DROP],
    [4, (b)],
    [IN],
    [203.0.113.0/24],
    [ANY],
    [ANY],
    [ANY],
    [ANY],
    [NEW, ESTABLISHED],
    [DROP],
    [5, (b)],
    [OUT],
    [ANY],
    [203.0.113.0/24],
    [ANY],
    [ANY],
    [ANY],
    [NEW, ESTABLISHED],
    [DROP],
    [6, (c)],
    [OUT],
    [ANY],
    [18.0.0.2],
    [TCP],
    [ANY],
    [20, 21],
    [NEW, ESTABLISHED],
    [REJECT],
    [7, (c)],
    [OUT],
    [ANY],
    [18.0.0.2],
    [TCP],
    [ANY],
    [22],
    [NEW, ESTABLISHED],
    [ACCEPT],
    [8, (c)],
    [IN],
    [18.0.0.2],
    [ANY],
    [TCP],
    [22],
    [ANY],
    [ESTABLISHED],
    [ACCEPT],
    [9, (d)],
    [IN],
    [198.51.100.0/24],
    [ANY],
    [TCP],
    [ANY],
    [22],
    [NEW,ESTABLISHED],
    [ACCEPT],
    [10, (d)],
    [OUT],
    [ANY],
    [198.51.100.0/24],
    [TCP],
    [22],
    [ANY],
    [ESTABLISHED],
    [ACCEPT],
    [11, (e)],
    [OUT],
    [ANY],
    [ANY],
    [ICMP],
    [],
    [],
    [NEW,ESTABLISHED],
    [ACCEPT],
    [12, (e)],
    [IN],
    [ANY],
    [ANY],
    [ICMP],
    [],
    [],
    [ESTABLISHED],
    [ACCEPT],
    [13, (f)],
    [OUT],
    [ANY],
    [ANY],
    [TCP, UDP],
    [ANY],
    [53],
    [NEW,ESTABLISHED],
    [ACCEPT],
    [14, (f)],
    [IN],
    [ANY],
    [ANY],
    [TCP, UDP],
    [53],
    [ANY],
    [ESTABLISHED],
    [ACCEPT],
    [15, (g)],
    [IN, OUT],
    [ANY],
    [ANY],
    [ANY],
    [ANY],
    [ANY],
    [NEW, ESTABLISHED],
    [DROP],
  )

+ ?

  For *DROP-ALL*: 4, 5, 1, 2, 13, 14, 6, 7, 8, 9, 10, 11, 12

  For *ALLOW-ALL*: 4, 5, 1, 2, 13, 14, 6, 7, 8, 9, 10, 11, 12, 15

+ ?

= Password Management

= Byzantine Link

= RPKI and ROA
