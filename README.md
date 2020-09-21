# cvss-calculator
Common Vulnerability Scoring System Calculator for v3.1, v3.0, v2.0, v1.0

## Installation

**Direct <script>**
```html
<script src="https://cdn.jsdelivr.net/npm/cvss-calculator/dist/cvss.js"></script>
```

```js
const cvss = new Cvss("Cvss Vector ...");
const baseScore = cvss.getBaseScore();
```
> Example: https://github.com/bugra9/cvss-calculator/tree/master/examples/browser

**ES Module**
```html
<script type="module">
    import 'https://cdn.jsdelivr.net/npm/cvss-calculator/dist/cvss.js'

    const cvss = new Cvss("Cvss Vector ...");
    const baseScore = cvss.getBaseScore();
</script>
```
> Example: https://github.com/bugra9/cvss-calculator/tree/master/examples/module-browser

**Builder such as Webpack (Vue, React, Angular, ...)**
```bash
yarn add cvss-calculator
# or
npm install cvss-calculator
```

```js
import Cvss from 'cvss-calculator';

const cvss = new Cvss("Cvss Vector ...");
const baseScore = cvss.getBaseScore();
```

**Node.js**
```bash
yarn add cvss-calculator
# or
npm install cvss-calculator
```

```js
import Cvss from 'cvss-calculator';

const cvss = new Cvss("Cvss Vector ...");
const baseScore = cvss.getBaseScore();
```
> Example: https://github.com/bugra9/cvss-calculator/blob/master/examples/node.js/index.js

## Usage
```js
import Cvss from 'cvss-calculator';

const cvss = new Cvss("Cvss Vector ...");
const baseScore = cvss.getBaseScore();
const rating = cvss.getRating();
const impactScore = cvss.getImpactScore();
const exploitabilityScore = cvss.getExploitabilityScore();
const temporalScore = cvss.getTemporalScore();
const environmentalScore = cvss.getEnvironmentalScore();

const cvssVersion = cvss.getVersion();
const cvssVector = cvss.getVector();
const cvssLongVector = cvss.getLongVector();

const cvss2 = new Cvss("Cvss Vector ...");
const isEqual = cvss.isEqual(cvss2);
```
