# Sanity check

> Zdobądź flagę dołączając na nasz serwer Discorda. Link z zaproszeniem znajdziesz poniżej.

## Solution
Ah yes, that's a tough one. Eventually one can find that the following JavaScript solution works:
```js
Array.from(document.querySelectorAll('div[class^="topic__"]')[0].querySelectorAll('span')).map(x => x.textContent).join(" ").match(/ecsc25\{[^}]*\}/)[0]
```

## Flag
`ecsc25{welcome-to-ecsc-2025!warsaw-here-i-come!}`
