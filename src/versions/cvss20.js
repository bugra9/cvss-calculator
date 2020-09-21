/*
        ========= Base (Required) =========
    [AV] Access Vector                  : [N,A,L]           [Network, Adjacent Network, Local]
    [AC] Access Complexity              : [L,M,H]           [Low, Medium, High]
    [Au] Authentication                 : [N,S,M]           [None, Single, Multiple]
    [C] Confidentiality                 : [C,P,N]           [Complete, Partial, None]
    [I] Integrity                       : [C,P,N]           [Complete, Partial, None]
    [A] Availability                    : [C,P,N]           [Complete, Partial, None]

        ========= Temporal =========
    [E] Exploitability                  : [ND,H,F,POC,U]    [Not Defined, High, Functional, Proof of Concept, Unproven]
    [RL] Remediation Level              : [ND,U,W,TF,OF]    [Not Defined, Unavailable, Workaround, Temporary Fix, Official Fix]
    [RC] Report Confidence              : [ND,C,UR,UC]      [Not Defined, Confirmed, Uncorroborated, Unconfirmed]

        ========= Environmental =========
    [CR] Confidentiality Requirement    : [ND,H,M,L]        [Not Defined, High, Medium, Low]
    [IR] Integrity Requirement          : [ND,H,M,L]        [Not Defined, High, Medium, Low]
    [AR] Availability Requirement       : [ND,H,M,L]        [Not Defined, High, Medium, Low]
    [CDP] Collateral Damage Potential   : [ND,H,MH,LM,L,N]  [Not Defined, High, Medium-High, Low-Medium, Low, None]
    [TD] Target Distribution            : [ND,H,M,L,N]      [Not Defined, High, Medium, Low, None]
*/

import { getMetricCodeMap, round } from '../utils.js';

const metricMapException = {
    'Authentication': 'Au',
    'Uncorroborated': 'UR',
    'Unconfirmed': 'UC',
    'Medium-High': 'MH',
    'Low-Medium': 'LM',
};

const metric = {};
metric['Access Vector'] = {
    'Network': 1.0,
    'Adjacent Network': 0.646,
    'Local': 0.395,
};

metric['Access Complexity'] = {
    'Low': 0.71,
    'Medium': 0.61,
    'High': 0.35,
};

metric['Authentication'] = {
    'None': 0.704,
    'Single': 0.56,
    'Multiple': 0.45,
};

metric['Confidentiality'] = {
    'Complete': 0.660,
    'Partial': 0.275,
    'None': 0
};

metric['Integrity'] = {
    'Complete': 0.660,
    'Partial': 0.275,
    'None': 0
};

metric['Availability'] = {
    'Complete': 0.660,
    'Partial': 0.275,
    'None': 0
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
    'Medium-High': 0.4,
    'Low-Medium': 0.3,
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

metric['Confidentiality Requirement'] = {
    'Not Defined': 1,
    'High': 1.51,
    'Medium': 1,
    'Low': 0.5,
};

metric['Integrity Requirement'] = {
    'Not Defined': 1,
    'High': 1.51,
    'Medium': 1,
    'Low': 0.5,
};

metric['Availability Requirement'] = {
    'Not Defined': 1,
    'High': 1.51,
    'Medium': 1,
    'Low': 0.5,
};

metric.get = function(key, cvssObject) {
    if (!cvssObject[key]) return Object.values(this[key])[0];
    const value = this[key][cvssObject[key]];
    return typeof value === "function" ? value(cvssObject) : value;
};

const metricCodeMap = getMetricCodeMap(metric, metricMapException);

class Cvss20 {
    constructor(cvssObject) {
        this.cvss = cvssObject;
    }

    static getMetricCodeMap() {
        return metricCodeMap;
    }

    getImpactScore() {
        return 10.41 * (1 - (
            (1 - metric.get('Confidentiality', this.cvss)) *
            (1 - metric.get('Integrity', this.cvss)) *
            (1 - metric.get('Availability', this.cvss))
        ));
    }

    getExploitabilityScore() {
        return (
            20.0 *
            metric.get('Access Vector', this.cvss) *
            metric.get('Access Complexity', this.cvss) *
            metric.get('Authentication', this.cvss)
        );
    }

    getBaseScore() {
        const ISC = this.getImpactScore();
        const ESC = this.getExploitabilityScore();
        let baseScore = 0;

        if (ISC > 0) {
            baseScore = ( (0.6*ISC) + (0.4*ESC) - 1.5) * 1.176;
        }

        return round(baseScore);
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
        const AdjustedImpact = Math.min(10, 10.41 * (1 - (
            (1 - metric.get('Confidentiality', this.cvss) * metric.get('Confidentiality Requirement', this.cvss)) *
            (1 - metric.get('Integrity', this.cvss) * metric.get('Integrity Requirement', this.cvss)) *
            (1 - metric.get('Availability', this.cvss) * metric.get('Availability Requirement', this.cvss))
        )));
        const ESC = this.getExploitabilityScore();
        const AdjustedBase = ( (0.6*AdjustedImpact) + (0.4*ESC) - 1.5) * 1.176;
        const AdjustedTemporal = round(
            AdjustedBase *
            metric.get('Exploitability', this.cvss) *
            metric.get('Remediation Level', this.cvss) *
            metric.get('Report Confidence', this.cvss)
        );

        return round((AdjustedTemporal +
            (10 - AdjustedTemporal) *
            metric.get('Collateral Damage Potential', this.cvss)
        ) * metric.get('Target Distribution', this.cvss));
    }
}

export default Cvss20;
