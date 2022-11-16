const Cvss = require('../../../frontend/src/assets/scripts/cvss.js');

const c = new Cvss('CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:P/MAC:H/MPR:H/MUI:N/MS:C/MC:H/MI:H/MA:H'); // 6.8 5.9 6.1
console.log(`Base Score: ${c.getBaseScore()}, Rating: ${c.getRating()}, Impact Score: ${c.getImpactScore()}, Exploitability Score: ${c.getExploitabilityScore()}, Temporal Score: ${c.getTemporalScore()}, Environmental Score: ${c.getEnvironmentalScore()}`);
