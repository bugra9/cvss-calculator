/*
        ========= Base (Required) =========
    [AV] Access Vector                  : [R,L]             [Remote, Local]
    [AC] Access Complexity              : [L,H]             [Low, High]
    [Au] Authentication                 : [NR,R]            [Not Required, Required]
    [C] Confidentiality                 : [C,P,N]           [Complete, Partial, None]
    [I] Integrity                       : [C,P,N]           [Complete, Partial, None]
    [A] Availability                    : [C,P,N]           [Complete, Partial, None]
    [IB] Impact Bias                    : [A,I,C,N]         [Availability, Integrity, Confidentiality, Normal]

        ========= Temporal =========
    [E] Exploitability                  : [ND,H,F,POC,U]    [Not Defined, High, Functional, Proof of Concept, Unproven]
    [RL] Remediation Level              : [ND,U,W,TF,OF]    [Not Defined, Unavailable, Workaround, Temporary Fix, Official Fix]
    [RC] Report Confidence              : [ND,C,UR,UC]      [Not Defined, Confirmed, Uncorroborated, Unconfirmed]

        ========= Environmental =========
    [CDP] Collateral Damage Potential   : [ND,H,M,L,N]      [Not Defined, High, Medium, Low, None]
    [TD] Target Distribution            : [ND,H,M,L,N]      [Not Defined, High, Medium, Low, None]
*/

import { getMetricCodeMap, round } from '../utils.js';

const metricMapException = {
    'Authentication': 'Au',
    'Uncorroborated': 'UR',
    'Unconfirmed': 'UC',
};

const metric = {};
metric['Access Vector'] = {
    'Remote': 1.0,
    'Local': 0.7,
};

metric['Access Complexity'] = {
    'Low': 1.0,
    'High': 0.8,
};

metric['Authentication'] = {
    'Not Required': 1.0,
    'Required': 0.6,
};

metric['Confidentiality'] = {
    'Complete': 1,
    'Partial': 0.7,
    'None': 0
};

metric['Integrity'] = {
    'Complete': 1,
    'Partial': 0.7,
    'None': 0
};

metric['Availability'] = {
    'Complete': 1,
    'Partial': 0.7,
    'None': 0
};

metric['Impact Bias'] = { // [CIA]
    'Availability': [0.25, 0.25, 0.5],
    'Integrity': [0.25, 0.5, 0.25],
    'Confidentiality': [0.5, 0.25, 0.25],
    'Normal': [0.333, 0.333, 0.333],
};

metric['Exploitability'] = {
    'Not Defined': 1,
    'High': 1,
    'Functional': 0.95,
    'Proof of Concept': 0.9,
    'Unproven': 0.85,
};

metric['Remediation Level'] = {
    'Not Defined': 1,
    'Unavailable': 1,
    'Workaround': 0.95,
    'Temporary Fix ': 0.90,
    'Official Fix': 0.87,
};

metric['Report Confidence'] = {
    'Not Defined': 1,
    'Confirmed': 1,
    'Uncorroborated': 0.95,
    'Unconfirmed': 0.90,
};

metric['Collateral Damage Potential'] = {
    'Not Defined': 0,
    'High': 0.5,
    'Medium': 0.3,
    'Low': 0.1,
    'None': 0,
};

metric['Target Distribution'] = {
    'Not Defined': 1,
    'High': 1,
    'Medium': 0.75,
    'Low': 0.25,
    'None': 0,
};

metric.get = function(key, cvssObject) {
    if (!cvssObject[key]) return Object.values(this[key])[0];
    const value = this[key][cvssObject[key]];
    return typeof value === "function" ? value(cvssObject) : value;
};

const metricCodeMap = getMetricCodeMap(metric, metricMapException);

class Cvss10 {
    constructor(cvssObject) {
        this.cvss = cvssObject;
    }

    static getMetricCodeMap() {
        return metricCodeMap;
    }

    getImpactScore() {
        const impactBias = metric.get('Impact Bias', this.cvss);
        return (
            metric.get('Confidentiality', this.cvss) * impactBias[0] +
            metric.get('Integrity', this.cvss) * impactBias[1] +
            metric.get('Availability', this.cvss) * impactBias[2]
        );
    }

    getExploitabilityScore() {
        return (
            10 *
            metric.get('Access Vector', this.cvss) *
            metric.get('Access Complexity', this.cvss) *
            metric.get('Authentication', this.cvss)
        );
    }

    getBaseScore() {
        const ISC = this.getImpactScore();
        const ESC = this.getExploitabilityScore();

        return round(ISC * ESC);
    }

    getTemporalScore() {
        return round(
            this.getBaseScore() *
            metric.get('Exploitability', this.cvss) *
            metric.get('Remediation Level', this.cvss) *
            metric.get('Report Confidence', this.cvss)
        );
    }

    getEnvironmentalScore() {
        const temporalScore = this.getTemporalScore();

        return round((temporalScore +
            (10 - temporalScore) *
            metric.get('Collateral Damage Potential', this.cvss)
        ) * metric.get('Target Distribution', this.cvss));
    }
}

export default Cvss10;
