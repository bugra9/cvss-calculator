/*
        ========= Base (Required) =========
    [AV] Attack Vector                  : [N,A,L,P]     [Network, Adjacent Network, Local, Physical]
    [AC] Attack Complexity              : [L,H]         [Low, High]
    [PR] Privileges Required            : [N,L,H]       [None, Low, High]
    [UI] User Interaction               : [N,R]         [None, Required]
    [S] Scope                           : [U,C]         [Unchanged, Changed]
    [C] Confidentiality                 : [H,L,N]       [High, Low, None]
    [I] Integrity                       : [H,L,N]       [High, Low, None]
    [A] Availability                    : [H,L,N]       [High, Low, None]

        ========= Temporal =========
    [E] Exploit Code Maturity           : [X,H,F,P,U]   [Not Defined, High, Functional, Proof of Concept, Unproven]
    [RL] Remediation Level              : [X,U,W,T,O]   [Not Defined, Unavailable, Workaround, Temporary Fix, Official Fix]
    [RC] Report Confidence              : [X,C,R,U]     [Not Defined, Confirmed, Reasonable, Unknown]

        ========= Environmental =========
    [CR] Confidentiality Requirement    : [X,H,M,L]     [Not Defined, High, Medium, Low]
    [IR] Integrity Requirement          : [X,H,M,L]     [Not Defined, High, Medium, Low]
    [AR] Availability Requirement       : [X,H,M,L]     [Not Defined, High, Medium, Low]
    [MAV] Modified Attack Vector        : [X,N,A,L,P]   [Not Defined, Network, Adjacent Network, Local, Physical]
    [MAC] Modified Attack Complexity    : [X,L,H]       [Not Defined, Low, High]
    [MPR] Modified Privileges Required  : [X,N,L,H]     [Not Defined, None, Low, High]
    [MUI] Modified User Interaction     : [X,N,R]       [Not Defined, None, Required]
    [MS] Modified Scope                 : [X,U,C]       [Not Defined, Unchanged, Changed]
    [MC] Modified Confidentiality       : [X,N,L,H]     [Not Defined, High, Low, None]
    [MI] Modified Integrity             : [X,N,L,H]     [Not Defined, High, Low, None]
    [MA] Modified Availability          : [X,N,L,H]     [Not Defined, High, Low, None]
*/

import { getMetricCodeMap, roundUp } from '../utils.js';

const metricMapException = {
    'Exploit Code Maturity': 'E',
    'Not Defined': 'X',
};

const metric = {};
metric['Attack Vector'] = {
    'Network': 0.85,
    'Adjacent Network': 0.62,
    'Local': 0.55,
    'Physical': 0.2,
};
metric['Modified Attack Vector'] = metric['Attack Vector'];

metric['Attack Complexity'] = {
    'Low': 0.77,
    'High': 0.44,
};
metric['Modified Attack Complexity'] = metric['Attack Complexity'];

metric['Privilege Required'] = {
    'None': 0.85,
    'Low': (cvss) => cvss['Scope'] === 'Changed' ? 0.68 : 0.62,
    'High': (cvss) => cvss['Scope'] === 'Changed' ? 0.50 : 0.27,
};
metric['Modified Privilege Required'] = {
    'None': 0.85,
    'Low': (cvss) => cvss['Modified Scope'] === 'Changed' ? 0.68 : 0.62,
    'High': (cvss) => cvss['Modified Scope'] === 'Changed' ? 0.50 : 0.27,
};

metric['User Interaction'] = {
    'None': 0.85,
    'Required': 0.62,
};
metric['Modified User Interaction'] = metric['User Interaction'];

metric['Scope'] = {
    'Unchanged': 1,
    'Changed': 1,
};
metric['Modified Scope'] = metric['Scope'];

metric['Confidentiality'] = {
    'High': 0.56,
    'Low': 0.22,
    'None': 0
};
metric['Modified Confidentiality'] = metric['Confidentiality'];

metric['Integrity'] = {
    'High': 0.56,
    'Low': 0.22,
    'None': 0
};
metric['Modified Integrity'] = metric['Integrity'];

metric['Availability'] = {
    'High': 0.56,
    'Low': 0.22,
    'None': 0
};
metric['Modified Availability'] = metric['Availability'];

metric['Exploit Code Maturity'] = {
    'Not Defined': 1,
    'High': 1,
    'Functional': 0.97,
    'Proof of Concept': 0.94,
    'Unproven': 0.91,
};

metric['Remediation Level'] = {
    'Not Defined': 1,
    'Unavailable': 1,
    'Workaround': 0.97,
    'Temporary Fix ': 0.96,
    'Official Fix': 0.95,
};

metric['Report Confidence'] = {
    'Not Defined': 1,
    'Confirmed': 1,
    'Reasonable': 0.96,
    'Unknown': 0.92,
};

metric['Confidentiality Requirement'] = {
    'Not Defined': 1,
    'High': 1.5,
    'Medium': 1,
    'Low': 0.5,
};

metric['Integrity Requirement'] = {
    'Not Defined': 1,
    'High': 1.5,
    'Medium': 1,
    'Low': 0.5,
};

metric['Availability Requirement'] = {
    'Not Defined': 1,
    'High': 1.5,
    'Medium': 1,
    'Low': 0.5,
};

metric.get = function(key, cvssObject, altKey) {
    if (!cvssObject[key] || cvssObject[key] === 'Not Defined')
        return altKey ? this[key][cvssObject[altKey]] : Object.values(this[key])[0];
    const value = this[key][cvssObject[key]];
    return typeof value === "function" ? value(cvssObject) : value;
};

const metricCodeMap = getMetricCodeMap(metric, metricMapException);

class Cvss31 {
    constructor(cvssObject) {
        this.cvss = cvssObject;
    }

    static getMetricCodeMap() {
        return metricCodeMap;
    }

    getImpactScore() {
        const ISCbase = 1 - (
            (1 - metric.get('Confidentiality', this.cvss)) *
            (1 - metric.get('Integrity', this.cvss)) *
            (1 - metric.get('Availability', this.cvss))
        );
        return this.cvss['Scope'] === 'Changed' ? 7.52 * (ISCbase-0.029) - 3.25 * Math.pow(ISCbase-0.02, 15) : 6.42 * ISCbase;
    }

    getExploitabilityScore() {
        return (
            8.22 *
            metric.get('Attack Vector', this.cvss) *
            metric.get('Attack Complexity', this.cvss) *
            metric.get('Privilege Required', this.cvss) *
            metric.get('User Interaction', this.cvss)
        );
    }

    getBaseScore() {
        const ISC = this.getImpactScore();
        const ESC = this.getExploitabilityScore();
        let baseScore = 0;

        if (ISC > 0) {
            if (this.cvss['Scope'] === 'Changed')
                baseScore = Math.min(1.08 * (ISC + ESC), 10);
            else
                baseScore = Math.min(ISC + ESC, 10);
        }

        return roundUp(baseScore);
    }

    getTemporalScore() {
        return roundUp(
            this.getBaseScore() *
            metric.get('Exploit Code Maturity', this.cvss) *
            metric.get('Remediation Level', this.cvss) *
            metric.get('Report Confidence', this.cvss)
        );
    }

    getEnvironmentalScore() {
        let environmentalScore = 0;
        const ISCmodified = Math.min(1 - (
            (1 - metric.get('Modified Confidentiality', this.cvss, 'Confidentiality') * metric.get('Confidentiality Requirement', this.cvss)) *
            (1 - metric.get('Modified Integrity',  this.cvss, 'Integrity') * metric.get('Integrity Requirement', this.cvss)) *
            (1 - metric.get('Modified Availability', this.cvss, 'Availability') * metric.get('Availability Requirement', this.cvss))
        ), 0.915);
        const mISC = this.cvss['Modified Scope'] === 'Changed' ? 7.52 * (ISCmodified - 0.029) - 3.25 * Math.pow(ISCmodified * 0.9731 - 0.02, 13) : 6.42 * ISCmodified;
        const mESC = (
            8.22 *
            metric.get('Modified Attack Vector',  this.cvss, 'Attack Vector') *
            metric.get('Modified Attack Complexity', this.cvss, 'Attack Complexity') *
            metric.get('Modified Privilege Required', this.cvss, 'Privilege Required') *
            metric.get('Modified User Interaction', this.cvss, 'User Interaction')
        );

        if (mISC > 0) {
            if (this.cvss['Modified Scope'] === 'Changed')
                environmentalScore = (
                    roundUp(Math.min(1.08 * (mISC + mESC), 10)) *
                    metric.get('Exploit Code Maturity', this.cvss) *
                    metric.get('Remediation Level', this.cvss) *
                    metric.get('Report Confidence', this.cvss)
                );
            else
                environmentalScore = (
                    roundUp(Math.min(mISC + mESC, 10)) *
                    metric.get('Exploit Code Maturity', this.cvss) *
                    metric.get('Remediation Level', this.cvss) *
                    metric.get('Report Confidence', this.cvss)
                );
        }
        return roundUp(environmentalScore);
    }
}

export default Cvss31;
