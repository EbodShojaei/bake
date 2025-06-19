const orRegex = /\s*\|\|\s*/g;
const andRegex = /\s*&&\s*/g;
const rangeRegex = /^\s*([<>=~^]*)\s*([\d.x]+)(-[^\s]+)?\s*/;
const xRegex = /[.]x/g;
/**
 * Check if the version is within the range
 * @param subject The version to check against the range
 * @param range The range to check the version against
 */
export default function withinVersionRange(subject, range) {
    // prepare and verify subject
    subject = String(subject);
    const [subjectMajor = null, subjectMinor = null, subjectPatch = null] = subject.split('.');
    if (subjectMajor === null)
        throw new Error(`subject was invalid: ${JSON.stringify(subject)}`);
    const subjectMajorNumber = Number(subjectMajor || 0);
    const subjectMinorNumber = Number(subjectMinor || 0);
    const subjectPatchNumber = Number(subjectPatch || 0);
    // cycle through the conditions
    const orRanges = Array.isArray(range)
        ? range.slice()
        : String(range).split(orRegex);
    for (const orRange of orRanges) {
        let orResult = false;
        const andRanges = String(orRange).split(andRegex);
        for (const andRange of andRanges) {
            let andResult = false;
            // process range
            const [match, comparator, targetRaw, prerelease] = String(andRange).match(rangeRegex) || [];
            const target = (targetRaw || '').replace(xRegex, '');
            // // log
            // console.log({
            // 	orRange,
            // 	andRange,
            // 	match,
            // 	comparator,
            // 	target,
            // 	prerelease,
            // })
            // prepare and verify target
            const [targetMajor = null, targetMinor = null, targetPatch = null] = target.split('.');
            if (!match || !target || targetMajor == null || prerelease)
                throw new Error(`range condition was invalid: ${JSON.stringify(andRange)}`);
            const targetMajorNumber = Number(targetMajor || 0);
            const targetMinorNumber = Number(targetMinor || 0);
            const targetPatchNumber = Number(targetPatch || 0);
            // is there more range matches? add it to and condition
            const remainder = String(andRange).slice(match.length);
            if (remainder)
                andRanges.push(remainder);
            // handle comparator
            switch (comparator) {
                case '^':
                    if (subjectMajorNumber === targetMajorNumber) {
                        if (subjectMinorNumber === targetMinorNumber) {
                            if (subjectPatchNumber >= targetPatchNumber) {
                                andResult = true;
                            }
                        }
                        else if (subjectMinorNumber >= targetMinorNumber) {
                            andResult = true;
                        }
                    }
                    break;
                case '~':
                    if (subjectMajorNumber === targetMajorNumber) {
                        if (subjectMinor !== null &&
                            subjectMinorNumber === targetMinorNumber) {
                            if (subjectPatchNumber >= targetPatchNumber) {
                                andResult = true;
                            }
                        }
                    }
                    break;
                case '>=':
                    if (subjectMajorNumber === targetMajorNumber) {
                        if (subjectMinorNumber === targetMinorNumber) {
                            if (subjectPatchNumber >= targetPatchNumber) {
                                andResult = true;
                            }
                        }
                        else if (subjectMinorNumber >= targetMinorNumber) {
                            andResult = true;
                        }
                    }
                    else if (subjectMajorNumber >= targetMajorNumber) {
                        andResult = true;
                    }
                    break;
                case '>':
                    if (subjectMajorNumber === targetMajorNumber) {
                        if (targetMinor === null) {
                            // x > x = false
                            // x.y > x = false
                        }
                        else if (subjectMinorNumber === targetMinorNumber) {
                            if (targetPatch === null) {
                                // x.y > x.y = false
                                // x.y.z > x.y = false
                            }
                            else if (subjectPatchNumber > targetPatchNumber) {
                                andResult = true;
                            }
                        }
                        else if (subjectMinorNumber > targetMinorNumber) {
                            andResult = true;
                        }
                    }
                    else if (subjectMajorNumber > targetMajorNumber) {
                        andResult = true;
                    }
                    break;
                case '<':
                    if (subjectMajorNumber === targetMajorNumber) {
                        if (subjectMinor === null) {
                            // x < x = false
                            // x < x.y = false
                        }
                        else if (subjectMinorNumber === targetMinorNumber) {
                            if (subjectPatch === null) {
                                // x.y < x.y = false
                                // x.y < x.y.z = false
                            }
                            else if (subjectPatchNumber < targetPatchNumber) {
                                andResult = true;
                            }
                        }
                        else if (subjectMinorNumber < targetMinorNumber) {
                            andResult = true;
                        }
                    }
                    else if (subjectMajorNumber < targetMajorNumber) {
                        andResult = true;
                    }
                    break;
                case '<=':
                    if (subjectMajorNumber === targetMajorNumber) {
                        if (subjectMinor === null) {
                            if (targetMinor === null) {
                                // x <= x = true
                                andResult = true;
                            }
                            // x <= x.y = false
                        }
                        else if (targetMinor === null) {
                            // x.y <= x = true
                            andResult = true;
                        }
                        else if (subjectMinorNumber === targetMinorNumber) {
                            if (subjectPatch === null) {
                                if (targetPatch === null) {
                                    // x.y <= x.y = true
                                    andResult = true;
                                }
                                // x.y <= x.y.z = false
                            }
                            else if (targetPatch === null) {
                                // x.y.z <= x.y = true
                                andResult = true;
                            }
                            else if (subjectPatchNumber <= targetPatchNumber) {
                                // x.y.z <= x.y.z = true
                                andResult = true;
                            }
                        }
                        else if (subjectMinorNumber <= targetMinorNumber) {
                            andResult = true;
                        }
                    }
                    else if (subjectMajorNumber <= targetMajorNumber) {
                        andResult = true;
                    }
                    break;
                case '=':
                case '':
                    if (subjectMajor === targetMajor) {
                        if (targetMinor === null) {
                            andResult = true;
                        }
                        else if (subjectMinor === targetMinor) {
                            if (targetPatch === null || subjectPatch === targetPatch) {
                                andResult = true;
                            }
                        }
                    }
                    break;
                default:
                    throw new Error(`range comparator was invalid: ${JSON.stringify(andRange)}`);
            }
            // if one of the and conditions failed, don't continue and checks, and note failure to the or condition
            if (!andResult) {
                orResult = false;
                break;
            }
            else {
                // otherwise note success to the or condition
                orResult = true;
            }
        }
        // if the entire and conditions passed, then we can break out of the or conditions
        if (orResult) {
            return true;
        }
    }
    // nothing passed
    return false;
}
