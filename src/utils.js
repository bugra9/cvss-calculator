function getMetricCodeMap(metric, exceptions = {}) {
    const output = {};
    for (const [mKey, mValue] of Object.entries(metric)) {
        const newMKey = exceptions[mKey] || mKey.split(' ').map(k => k.charAt(0)).join('').toUpperCase();
        output[newMKey] = { name: mKey };
        for (const [key] of Object.entries(mValue)) {
            const newKey = exceptions[key] || key.split(' ').map(k => k.charAt(0)).join('').toUpperCase();
            output[newMKey][newKey] = key;
        }
    }
    for (const [mKey, mValue] of Object.entries(output)) {
        if (mKey.length > 1 && !output[mKey.charAt(0)])
            output[mKey.charAt(0)] = mValue;

        for (const [key, value] of Object.entries(mValue)) {
            if (key.length > 1 && !mValue[key.charAt(0)])
                mValue[key.charAt(0)] = value;
        }
    }
    return output;
}

function round10000(num) {
    return Math.round((num + Number.EPSILON) * 100000) / 100000;
}

function round(num) {
    return Math.round((num + Number.EPSILON) * 10) / 10;
}

function roundUp(num) {
    return Math.ceil(round10000(num * 10)) / 10;
}

function splitCvssVector(vector) {
    const output = {};
    vector.split('/').forEach(v => {
        const temp = v.split(':');
        output[temp[0]] = temp[1];
    });
    return output;
}

function detectCvssVersion(cvssVectorObject) {
    if (cvssVectorObject['IB']) return '1.0';
    else if (cvssVectorObject['Au']) return '2.0';
    else return '3.1';
}

function parseCvssVector(vector, cvssClass, cvssClasses) {
    const regex = /^(CVSS:\d\.\d\/)?(AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH])(\/E:[XUPFH]\/RL:[XOTWU]\/RC:[XURC]\/CR:[XMLH]\/IR:[XLMH]\/AR:[XLMH]\/MAV:[XNALP]\/MAC:[XLH]\/MPR:[XNLH]\/MUI:[XNR]\/MS:[XUC]\/MC:[XNLH]\/MI:[XNLH]\/MA:[XNLH])?$/gm;

    if (!regex.exec(vector))
        return undefined;

    const output = { short: {}, long: {}};
    output.short = splitCvssVector(vector);
    if (!output.short.CVSS) output.short.CVSS = detectCvssVersion(output.short);
    const map = (cvssClass || cvssClasses[output.short.CVSS]).getMetricCodeMap();

    for (const [mKey, mValue] of Object.entries(output.short)) {
        if (map[mKey]) output.long[map[mKey].name] = map[mKey][mValue];
    }

    return output;
}

exports.getMetricCodeMap = getMetricCodeMap;
exports.roundUp = roundUp;
exports.round = round;
exports.parseCvssVector = parseCvssVector;
