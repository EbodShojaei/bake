<!-- TITLE/ -->

# Is Text or Binary?

<!-- /TITLE -->

<!-- BADGES/ -->

<span class="badge-githubworkflow"><a href="https://github.com/bevry/istextorbinary/actions?query=workflow%3Abevry" title="View the status of this project's GitHub Workflow: bevry"><img src="https://github.com/bevry/istextorbinary/workflows/bevry/badge.svg" alt="Status of the GitHub Workflow: bevry" /></a></span>
<span class="badge-npmversion"><a href="https://npmjs.org/package/istextorbinary" title="View this project on NPM"><img src="https://img.shields.io/npm/v/istextorbinary.svg" alt="NPM version" /></a></span>
<span class="badge-npmdownloads"><a href="https://npmjs.org/package/istextorbinary" title="View this project on NPM"><img src="https://img.shields.io/npm/dm/istextorbinary.svg" alt="NPM downloads" /></a></span>
<br class="badge-separator" />
<span class="badge-githubsponsors"><a href="https://github.com/sponsors/balupton" title="Donate to this project using GitHub Sponsors"><img src="https://img.shields.io/badge/github-donate-yellow.svg" alt="GitHub Sponsors donate button" /></a></span>
<span class="badge-thanksdev"><a href="https://thanks.dev/u/gh/bevry" title="Donate to this project using ThanksDev"><img src="https://img.shields.io/badge/thanksdev-donate-yellow.svg" alt="ThanksDev donate button" /></a></span>
<span class="badge-patreon"><a href="https://patreon.com/bevry" title="Donate to this project using Patreon"><img src="https://img.shields.io/badge/patreon-donate-yellow.svg" alt="Patreon donate button" /></a></span>
<span class="badge-liberapay"><a href="https://liberapay.com/bevry" title="Donate to this project using Liberapay"><img src="https://img.shields.io/badge/liberapay-donate-yellow.svg" alt="Liberapay donate button" /></a></span>
<span class="badge-buymeacoffee"><a href="https://buymeacoffee.com/balupton" title="Donate to this project using Buy Me A Coffee"><img src="https://img.shields.io/badge/buy%20me%20a%20coffee-donate-yellow.svg" alt="Buy Me A Coffee donate button" /></a></span>
<span class="badge-opencollective"><a href="https://opencollective.com/bevry" title="Donate to this project using Open Collective"><img src="https://img.shields.io/badge/open%20collective-donate-yellow.svg" alt="Open Collective donate button" /></a></span>
<span class="badge-crypto"><a href="https://bevry.me/crypto" title="Donate to this project using Cryptocurrency"><img src="https://img.shields.io/badge/crypto-donate-yellow.svg" alt="crypto donate button" /></a></span>
<span class="badge-paypal"><a href="https://bevry.me/paypal" title="Donate to this project using Paypal"><img src="https://img.shields.io/badge/paypal-donate-yellow.svg" alt="PayPal donate button" /></a></span>
<br class="badge-separator" />
<span class="badge-discord"><a href="https://discord.gg/nQuXddV7VP" title="Join this project's community on Discord"><img src="https://img.shields.io/discord/1147436445783560193?logo=discord&amp;label=discord" alt="Discord server badge" /></a></span>
<span class="badge-twitch"><a href="https://www.twitch.tv/balupton" title="Join this project's community on Twitch"><img src="https://img.shields.io/twitch/status/balupton?logo=twitch" alt="Twitch community badge" /></a></span>

<!-- /BADGES -->

<!-- DESCRIPTION/ -->

Determine if a filename and/or buffer is text or binary. Smarter detection than the other solutions.

<!-- /DESCRIPTION -->


Determination works like so:

1. Extension Check: If filename is available, check if any of its extensions (from right to left) are an [text extension](https://github.com/bevry/textextensions) or a [binary extension](https://github.com/bevry/binaryextensions), this is near instant.
2. Contents Check: If no filename was provided, or the extension check was indeterminate, then check the contents of the buffer.

The extension check will check each of the filename's extensions, from right to left. This is done as certain applications utilise multiple extensions for transformations, such as `app.x.y` may tell a compiler to transform from `x` format to `y` format, in this case perhaps `x` is not a recognized extension but `y` is, in which case we can make use of that to provide superior accuracy and convenience compared to just checking the rightmost extension.

The contents check (with the default options) will check 24 bytes at the start, middle, and end of the buffer. History has shown that checking all three locations is mandatory for accuracy, and that anything less is not accurate. This technique offers superior performance while still offering superior accuracy. Alternatives generally just do 1000 bytes at the start, which is slower, and inaccurate.

One cannot just do the contents check alone because UTF16 characters are indistinguishable from binary which would return an inaccurate result, hence why the combination is necessary for accuracy, with performance for known extensions a side-effect.

As such, this library's combination of extension check (if filename is provided), then contents check (if buffer is provided), offers superior performance and accuracy to alternatives.

Ever since 2012, this module's superior accuracy and performance has been essential to the operation of [DocPad](https://docpad.org) and its other dependents.

## Usage

[Complete API Documentation.](http://master.istextorbinary.bevry.surge.sh/docs/)

```typescript
import { isText, isBinary, getEncoding } from 'istextorbinary'
```

or

```javascript
const { isText, isBinary, getEncoding } = require('istextorbinary')
```

then

```javascript
isText(aFilename) // returns true if a text file otherwise false, checks only filename
isText(null, aBuffer) // returns true if a text file otherwise false, checks only buffer
isText(aFilename, aBuffer) // returns true if a text file otherwise false, checks filename then buffer
isText(null, null) // returns null

isBinary(aFilename) // returns true if a binary file otherwise false, checks only filename
isBinary(null, aBuffer) // returns true if a binary file otherwise false, checks only buffer
isBinary(aFilename, aBuffer) // returns true if a binary file otherwise false, checks filename then buffer
isBinary(null, null) // returns null

getEncoding(aBuffer) // returns 'binary' if it contained non-utf8 characters, otherwise returns 'utf8'
```

<!-- INSTALL/ -->

## Install

### [npm](https://npmjs.com "npm is a package manager for javascript")

-   Install: `npm install --save istextorbinary`
-   Import: `import * as pkg from ('istextorbinary')`
-   Require: `const pkg = require('istextorbinary')`

### [Deno](https://deno.land "Deno is a secure runtime for JavaScript and TypeScript, it is an alternative for Node.js")

``` typescript
import * as pkg from 'https://unpkg.com/istextorbinary@^9.5.0/edition-deno/index.ts'
```
### [Skypack](https://www.skypack.dev "Skypack is a JavaScript Delivery Network for modern web apps")

``` html
<script type="module">
    import * as pkg from '//cdn.skypack.dev/istextorbinary@^9.5.0'
</script>
```
### [unpkg](https://unpkg.com "unpkg is a fast, global content delivery network for everything on npm")

``` html
<script type="module">
    import * as pkg from '//unpkg.com/istextorbinary@^9.5.0'
</script>
```
### [jspm](https://jspm.io "Native ES Modules CDN")

``` html
<script type="module">
    import * as pkg from '//dev.jspm.io/istextorbinary@9.5.0'
</script>
```
### [Editions](https://editions.bevry.me "Editions are the best way to produce and consume packages you care about.")

This package is published with the following editions:
-   `istextorbinary` aliases `istextorbinary/index.cjs` which uses the [Editions Autoloader](https://github.com/bevry/editions "You can use the Editions Autoloader to autoload the appropriate edition for your consumers environment") to automatically select the correct edition for the consumer's environment
-   `istextorbinary/source/index.ts` is [TypeScript](https://www.typescriptlang.org/ "TypeScript is a typed superset of JavaScript that compiles to plain JavaScript.") source code with [Import](https://babeljs.io/docs/learn-es2015/#modules "ECMAScript Modules") for modules
-   `istextorbinary/edition-browsers/index.js` is [TypeScript](https://www.typescriptlang.org/ "TypeScript is a typed superset of JavaScript that compiles to plain JavaScript.") compiled against [ES2022](https://en.wikipedia.org/wiki/ES2022 "ECMAScript 2022") for web browsers with [Import](https://babeljs.io/docs/learn-es2015/#modules "ECMAScript Modules") for modules
-   `istextorbinary/edition-es2022/index.js` is [TypeScript](https://www.typescriptlang.org/ "TypeScript is a typed superset of JavaScript that compiles to plain JavaScript.") compiled against [ES2022](https://en.wikipedia.org/wiki/ES2022 "ECMAScript 2022") for [Node.js](https://nodejs.org "Node.js is a JavaScript runtime built on Chrome's V8 JavaScript engine") 14 || 16 || 18 || 20 || 21 with [Require](https://nodejs.org/dist/latest-v5.x/docs/api/modules.html "Node/CJS Modules") for modules
-   `istextorbinary/edition-es2017/index.js` is [TypeScript](https://www.typescriptlang.org/ "TypeScript is a typed superset of JavaScript that compiles to plain JavaScript.") compiled against [ES2017](https://en.wikipedia.org/wiki/ES2017 "ECMAScript 2017") for [Node.js](https://nodejs.org "Node.js is a JavaScript runtime built on Chrome's V8 JavaScript engine") 6 || 8 || 10 || 12 || 14 || 16 || 18 || 20 || 21 with [Require](https://nodejs.org/dist/latest-v5.x/docs/api/modules.html "Node/CJS Modules") for modules
-   `istextorbinary/edition-es5/index.js` is [TypeScript](https://www.typescriptlang.org/ "TypeScript is a typed superset of JavaScript that compiles to plain JavaScript.") compiled against ES5 for [Node.js](https://nodejs.org "Node.js is a JavaScript runtime built on Chrome's V8 JavaScript engine") 4 || 6 || 8 || 10 || 12 || 14 || 16 || 18 || 20 || 21 with [Require](https://nodejs.org/dist/latest-v5.x/docs/api/modules.html "Node/CJS Modules") for modules
-   `istextorbinary/edition-es2017-esm/index.js` is [TypeScript](https://www.typescriptlang.org/ "TypeScript is a typed superset of JavaScript that compiles to plain JavaScript.") compiled against [ES2017](https://en.wikipedia.org/wiki/ES2017 "ECMAScript 2017") for [Node.js](https://nodejs.org "Node.js is a JavaScript runtime built on Chrome's V8 JavaScript engine") 12 || 14 || 16 || 18 || 20 || 21 with [Import](https://babeljs.io/docs/learn-es2015/#modules "ECMAScript Modules") for modules
-   `istextorbinary/edition-types/index.d.ts` is [TypeScript](https://www.typescriptlang.org/ "TypeScript is a typed superset of JavaScript that compiles to plain JavaScript.") compiled Types with [Import](https://babeljs.io/docs/learn-es2015/#modules "ECMAScript Modules") for modules
-   `istextorbinary/edition-deno/index.ts` is [TypeScript](https://www.typescriptlang.org/ "TypeScript is a typed superset of JavaScript that compiles to plain JavaScript.") source code made to be compatible with [Deno](https://deno.land "Deno is a secure runtime for JavaScript and TypeScript, it is an alternative to Node.js")

<!-- /INSTALL -->

<!-- HISTORY/ -->

## History

[Discover the release history by heading on over to the `HISTORY.md` file.](https://github.com/bevry/istextorbinary/blob/HEAD/HISTORY.md#files)

<!-- /HISTORY -->

<!-- BACKERS/ -->

## Backers

### Code

[Discover how to contribute via the `CONTRIBUTING.md` file.](https://github.com/bevry/istextorbinary/blob/HEAD/CONTRIBUTING.md#files)

#### Authors

-   [Benjamin Lupton](https://balupton.com) — Accelerating collaborative wisdom.

#### Maintainers

-   [Benjamin Lupton](https://balupton.com) — Accelerating collaborative wisdom.
-   [Michael Duane Mooring](https://mdm.cc) — We are the space generation; and if you don't know, https://www.spaceforce.mil https://www.virgingalactic.com https://www.spacex.com now you know.
-   [Rob Loach](https://github.com/robloach)

#### Contributors

-   [Benjamin Lupton](https://github.com/balupton) — [view contributions](https://github.com/bevry/istextorbinary/commits?author=balupton "View the GitHub contributions of Benjamin Lupton on repository bevry/istextorbinary")
-   [Ian Sibner](https://github.com/sibnerian) — [view contributions](https://github.com/bevry/istextorbinary/commits?author=sibnerian "View the GitHub contributions of Ian Sibner on repository bevry/istextorbinary")
-   [Kukhyeon Heo](https://github.com/sainthkh) — [view contributions](https://github.com/bevry/istextorbinary/commits?author=sainthkh "View the GitHub contributions of Kukhyeon Heo on repository bevry/istextorbinary")
-   [Michael Duane Mooring](https://github.com/mikeumus) — [view contributions](https://github.com/bevry/istextorbinary/commits?author=mikeumus "View the GitHub contributions of Michael Duane Mooring on repository bevry/istextorbinary")
-   [Rob Loach](https://github.com/robloach) — [view contributions](https://github.com/bevry/istextorbinary/commits?author=robloach "View the GitHub contributions of Rob Loach on repository bevry/istextorbinary")
-   [Sean](https://github.com/AlbinoDrought) — [view contributions](https://github.com/bevry/istextorbinary/commits?author=AlbinoDrought "View the GitHub contributions of Sean on repository bevry/istextorbinary")
-   [shinnn](https://github.com/shinnn) — [view contributions](https://github.com/bevry/istextorbinary/commits?author=shinnn "View the GitHub contributions of shinnn on repository bevry/istextorbinary")

### Finances

<span class="badge-githubsponsors"><a href="https://github.com/sponsors/balupton" title="Donate to this project using GitHub Sponsors"><img src="https://img.shields.io/badge/github-donate-yellow.svg" alt="GitHub Sponsors donate button" /></a></span>
<span class="badge-thanksdev"><a href="https://thanks.dev/u/gh/bevry" title="Donate to this project using ThanksDev"><img src="https://img.shields.io/badge/thanksdev-donate-yellow.svg" alt="ThanksDev donate button" /></a></span>
<span class="badge-patreon"><a href="https://patreon.com/bevry" title="Donate to this project using Patreon"><img src="https://img.shields.io/badge/patreon-donate-yellow.svg" alt="Patreon donate button" /></a></span>
<span class="badge-liberapay"><a href="https://liberapay.com/bevry" title="Donate to this project using Liberapay"><img src="https://img.shields.io/badge/liberapay-donate-yellow.svg" alt="Liberapay donate button" /></a></span>
<span class="badge-buymeacoffee"><a href="https://buymeacoffee.com/balupton" title="Donate to this project using Buy Me A Coffee"><img src="https://img.shields.io/badge/buy%20me%20a%20coffee-donate-yellow.svg" alt="Buy Me A Coffee donate button" /></a></span>
<span class="badge-opencollective"><a href="https://opencollective.com/bevry" title="Donate to this project using Open Collective"><img src="https://img.shields.io/badge/open%20collective-donate-yellow.svg" alt="Open Collective donate button" /></a></span>
<span class="badge-crypto"><a href="https://bevry.me/crypto" title="Donate to this project using Cryptocurrency"><img src="https://img.shields.io/badge/crypto-donate-yellow.svg" alt="crypto donate button" /></a></span>
<span class="badge-paypal"><a href="https://bevry.me/paypal" title="Donate to this project using Paypal"><img src="https://img.shields.io/badge/paypal-donate-yellow.svg" alt="PayPal donate button" /></a></span>

#### Sponsors

-   [Andrew Nesbitt](https://nesbitt.io) — Software engineer and researcher
-   [Balsa](https://balsa.com) — We're Balsa, and we're building tools for builders.
-   [Codecov](https://codecov.io) — Empower developers with tools to improve code quality and testing.
-   [Poonacha Medappa](https://poonachamedappa.com)
-   [Rob Morris](https://github.com/Rob-Morris)
-   [Sentry](https://sentry.io) — Real-time crash reporting for your web apps, mobile apps, and games.
-   [Syntax](https://syntax.fm) — Syntax Podcast

#### Donors

-   [Andrew Nesbitt](https://nesbitt.io)
-   [Armen Mkrtchian](https://mogoni.dev)
-   [Balsa](https://balsa.com)
-   [Chad](https://opencollective.com/chad8)
-   [Codecov](https://codecov.io)
-   [dr.dimitru](https://veliovgroup.com)
-   [Elliott Ditman](https://elliottditman.com)
-   [entroniq](https://gitlab.com/entroniq)
-   [GitHub](https://github.com/about)
-   [Hunter Beast](https://cryptoquick.com)
-   [Jean-Luc Geering](https://github.com/jlgeering)
-   [Michael Duane Mooring](https://mdm.cc)
-   [Michael Harry Scepaniak](https://michaelscepaniak.com)
-   [Mohammed Shah](https://github.com/smashah)
-   [Mr. Henry](https://mrhenry.be)
-   [Nermal](https://arjunaditya.vercel.app)
-   [Pleo](https://pleo.io)
-   [Poonacha Medappa](https://poonachamedappa.com)
-   [Rob Morris](https://github.com/Rob-Morris)
-   [Robert de Forest](https://github.com/rdeforest)
-   [Sentry](https://sentry.io)
-   [ServieJS](https://github.com/serviejs)
-   [Skunk Team](https://skunk.team)
-   [Syntax](https://syntax.fm)
-   [WriterJohnBuck](https://github.com/WriterJohnBuck)

<!-- /BACKERS -->

<!-- LICENSE/ -->

## License

Unless stated otherwise all works are:

-   Copyright &copy; [Benjamin Lupton](https://balupton.com)

and licensed under:

-   [Artistic License 2.0](http://spdx.org/licenses/Artistic-2.0.html)

<!-- /LICENSE -->
