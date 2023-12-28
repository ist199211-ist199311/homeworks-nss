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

+ TODO

+ TODO

+ TODO

+ TODO

+ TODO

+ TODO

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
