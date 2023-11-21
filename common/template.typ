#let cover_page(title: none, date: none) = {
  set page("a4")
  set text(12pt)
  let kthblue = rgb("#2258a5")
  show link: it => underline(stroke: 1pt + kthblue, text(fill: kthblue, it))
  show heading: set block(above: 1.4em, below: 1em)

  align(
    center + horizon,
  )[
    #image("KTH_logo_RGB_bla.svg", height: 100pt)

    #v(20pt)

    #heading(outlined: false)[#title]
    #heading(
      outlined: false,
      level: 2,
    )[EP2500 Networked Systems Security]

    #v(20pt)

    #grid(columns: (50%, 50%), align(center)[
      Diogo Correia\
      #link("mailto:diogotc@kth.se")
    ], align(center)[
      Rafael Oliveira\
      #link("mailto:rmfseo@kth.se")
    ])

    #v(20pt)

    #smallcaps[#date]

    KTH Royal Institute of Technology
  ]
}

#let header(title: none, authors: []) = {
  set text(10pt)
  smallcaps[#title - EP2500 NSS HT23]
  h(1fr)
  smallcaps[Diogo Correia, Rafael Oliveira]
  line(length: 100%, stroke: 0.5pt + rgb("#888"))
}

#let footer = {
  set align(right)
  set text(10pt)
  line(length: 100%, stroke: 0.5pt + rgb("#888"))
  [Page ]
  counter(page).display("1 of 1", both: true)
}

#let setup_page(content) = {
  set par(justify: true)
  set heading(numbering: "1.1.")

  content
}
