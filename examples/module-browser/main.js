import '../../../frontend/src/assets/scripts/cvss.js';

function calc(cvssVector) {
    const c = new Cvss(cvssVector);
    document.querySelector("#base").innerText = c.getBaseScore();
    document.querySelector("#rating").innerText = c.getRating();
    document.querySelector("#impact").innerText = c.getImpactScore();
    document.querySelector("#exploitability").innerText = c.getExploitabilityScore();
    document.querySelector("#temporal").innerText = c.getTemporalScore();
    document.querySelector("#environmental").innerText = c.getEnvironmentalScore();
}
calc('CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H/E:U/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:P/MAC:H/MPR:H/MUI:N/MS:C/MC:H/MI:H/MA:H');
