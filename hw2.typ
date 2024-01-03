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
