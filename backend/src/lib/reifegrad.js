/* Copyright (c) 2019, FIRST.ORG, INC.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* This JavaScript contains two main functions. Both take CVSS metric values and calculate CVSS scores for Base,
 * Temporal and Environmental metric groups, their associated severity ratings, and an overall Vector String.
 *
 * Use CVSS31.calculateCVSSFromMetrics if you wish to pass metric values as individual parameters.
 * Use CVSS31.calculateCVSSFromVector if you wish to pass metric values as a single Vector String.
 *
 * Changelog
 *
 * 2019-06-01  Darius Wiles   Updates for CVSS version 3.1:
 *
 *                            1) The CVSS31.roundUp1 function now performs rounding using integer arithmetic to
 *                               eliminate problems caused by tiny errors introduced during JavaScript math
 *                               operations. Thanks to Stanislav Kontar of Red Hat for suggesting and testing
 *                               various implementations.
 *
 *                            2) Environmental formulas changed to prevent the Environmental Score decreasing when
 *                               the value of an Environmental metric is raised. The problem affected a small
 *                               percentage of CVSS v3.0 metrics. The change is to the modifiedImpact
 *                               formula, but only affects scores where the Modified Scope is Changed (or the
 *                               Scope is Changed if Modified Scope is Not Defined).
 *
 *                            3) The JavaScript object containing everything in this file has been renamed from
 *                               "CVSS" to "CVSS31" to allow both objects to be included without causing a
 *                               naming conflict.
 *
 *                            4) Variable names and code order have changed to more closely reflect the formulas
 *                               in the CVSS v3.1 Specification Document.
 *
 *                            5) A successful call to calculateCVSSFromMetrics now returns sub-formula values.
 *
 *                            Note that some sets of metrics will produce different scores between CVSS v3.0 and
 *                            v3.1 as a result of changes 1 and 2. See the explanation of changes between these
 *                            two standards in the CVSS v3.1 User Guide for more details.
 *
 * 2018-02-15  Darius Wiles   Added a missing pair of parentheses in the Environmental score, specifically
 *                            in the code setting envScore in the main clause (not the else clause). It was changed
 *                            from "min (...), 10" to "min ((...), 10)". This correction does not alter any final
 *                            Environmental scores.
 *
 * 2015-08-04  Darius Wiles   Added CVSS.generateXMLFromMetrics and CVSS.generateXMLFromVector functions to return
 *                            XML string representations of: a set of metric values; or a Vector String respectively.
 *                            Moved all constants and functions to an object named "CVSS" to
 *                            reduce the chance of conflicts in global variables when this file is combined with
 *                            other JavaScript code. This will break all existing code that uses this file until
 *                            the string "CVSS." is prepended to all references. The "Exploitability" metric has been
 *                            renamed "Exploit Code Maturity" in the specification, so the same change has been made
 *                            in the code in this file.
 *
 * 2015-04-24  Darius Wiles   Environmental formula modified to eliminate undesirable behavior caused by subtle
 *                            differences in rounding between Temporal and Environmental formulas that often
 *                            caused the latter to be 0.1 lower than than the former when all Environmental
 *                            metrics are "Not defined". Also added a RoundUp1 function to simplify formulas.
 *
 * 2015-04-09  Darius Wiles   Added calculateCVSSFromVector function, license information, cleaned up code and improved
 *                            comments.
 *
 * 2014-12-12  Darius Wiles   Initial release for CVSS 3.0 Preview 2.
 */

// Constants used in the formula. They are not declared as "const" to avoid problems in older browsers.

var CVSS31 = {};

CVSS31.CVSSVersionIdentifier = "Reifegrad";
// CVSS31.exploitabilityCoefficient = 8.22;
// CVSS31.scopeCoefficient = 1.08;

// A regular expression to validate that a CVSS 3.1 vector string is well formed. It checks metrics and metric
// values. It does not check that a metric is specified more than once and it does not check that all base
// metrics are present. These checks need to be performed separately.

CVSS31.vectorStringRegex_31 = /^CVSS:3\.[01]\/((U:[X]|D:[X]|G:[X]|E:[X]|V:[X])\/)*(U:[X]|D:[X]|G:[X]|E:[X]|V:[X])$/;


// Associative arrays mapping each metric value to the constant defined in the CVSS scoring formula in the CVSS v3.1
// specification.

CVSS31.Weight = {
    U: {X: 0},
    D: {X: 1},
    G: {X: 2},
    E: {X: 3},
    V: {X: 4}
};

// CVSS31.Weight = {
//   R: {U: 0, D: 1, G: 2, E: 3, V: 4}
// };


// Severity rating bands, as defined in the CVSS v3.1 specification.

CVSS31.severityRatings  = [ { name: "Unvollständig",  top:  0.0},
                            { name: "Durchgeführt",   top:  1.0},
                            { name: "Gesteuert",      top:  2.0},
                            { name: "Etabliert",      top:  3.0},
                            { name: "Vorhersagbar",   top: 4.0} ];




/* ** CVSS31.calculateCVSSFromMetrics **
 *
 * Takes Base, Temporal and Environmental metric values as individual parameters. Their values are in the short format
 * defined in the CVSS v3.1 standard definition of the Vector String. For example, the AttackComplexity parameter
 * should be either "H" or "L".
 *
 * Returns Base, Temporal and Environmental scores, severity ratings, and an overall Vector String. All Base metrics
 * are required to generate this output. All Temporal and Environmental metric values are optional. Any that are not
 * passed default to "X" ("Not Defined").
 *
 * The output is an object which always has a property named "success".
 *
 * If no errors are encountered, success is Boolean "true", and the following other properties are defined containing
 * scores, severities and a vector string:
 *   baseMetricScore, baseSeverity,
 *   temporalMetricScore, temporalSeverity,
 *   environmentalMetricScore, environmentalSeverity,
 *   vectorString
 *
 * The following properties are also defined, and contain sub-formula values:
 *   baseISS, baseImpact, baseExploitability,
 *   environmentalMISS, environmentalModifiedImpact, environmentalModifiedExploitability
 *
 *
 * If errors are encountered, success is Boolean "false", and the following other properties are defined:
 *   errorType - a string indicating the error. Either:
 *                 "MissingBaseMetric", if at least one Base metric has not been defined; or
 *                 "UnknownMetricValue", if at least one metric value is invalid.
 *   errorMetrics - an array of strings representing the metrics at fault. The strings are abbreviated versions of the
 *                  metrics, as defined in the CVSS v3.1 standard definition of the Vector String.
 */
CVSS31.calculateCVSSFromMetrics = function (
  Unvollständig, Durchgeführt, Gesteuert, Etabliert, Vorhersagbar) {

  // If input validation fails, this array is populated with strings indicating which metrics failed validation.
  var badMetrics = [];

  // ENSURE ALL BASE METRICS ARE DEFINED
  //
  // We need values for all Base Score metrics to calculate scores.
  // If any Base Score parameters are undefined, create an array of missing metrics and return it with an error.

  if (typeof Unvollständig    === "undefined" || Unvollständig  === "") { badMetrics.push("U"); }
  if (typeof Durchgeführt   === "undefined" || Durchgeführt === "") { badMetrics.push("D"); }
  if (typeof Gesteuert      === "undefined" || Gesteuert    === "") { badMetrics.push("G"); }
  if (typeof Etabliert      === "undefined" || Etabliert    === "") { badMetrics.push("E"); }
  if (typeof Vorhersagbar   === "undefined" || Vorhersagbar === "") { badMetrics.push("V");  }

  // if (typeof Reifegrad === "undefined" || Reifegrad  === "") { badMetrics.push("R"); }

  if (badMetrics.length > 0) {
    return { success: false, errorType: "MissingBaseMetric", errorMetrics: badMetrics };
  }


  // STORE THE METRIC VALUES THAT WERE PASSED AS PARAMETERS
  //
  // Temporal and Environmental metrics are optional, so set them to "X" ("Not Defined") if no value was passed.

  var U = Unvollständig
  var D = Durchgeführt
  var G = Gesteuert
  var E = Etabliert
  var V = Vorhersagbar

  // var R = Reifegrad

  // CHECK VALIDITY OF METRIC VALUES
  //
  // Use the Weight object to ensure that, for every metric, the metric value passed is valid.
  // If any invalid values are found, create an array of their metrics and return it with an error.
  //
  // The Privileges Required (PR) weight depends on Scope, but when checking the validity of PR we must not assume
  // that the given value for Scope is valid. We therefore always look at the weights for Unchanged Scope when
  // performing this check. The same applies for validation of Modified Privileges Required (MPR).
  //
  // The Weights object does not contain "X" ("Not Defined") values for Environmental metrics because we replace them
  // with their Base metric equivalents later in the function. For example, an MAV of "X" will be replaced with the
  // value given for AV. We therefore need to explicitly allow a value of "X" for Environmental metrics.

  if (!CVSS31.Weight.R.hasOwnProperty(U))   { badMetrics.push("U"); }
  if (!CVSS31.Weight.D.hasOwnProperty(D))   { badMetrics.push("D"); }
  if (!CVSS31.Weight.G.hasOwnProperty(G)) { badMetrics.push("G"); }
  if (!CVSS31.Weight.E.hasOwnProperty(E))   { badMetrics.push("E"); }
  if (!CVSS31.Weight.V.hasOwnProperty(V))     { badMetrics.push("V"); }

  // if (!CVSS31.Weight.R.hasOwnProperty(U))   { badMetrics.push("U"); }
  // if (!CVSS31.Weight.R.hasOwnProperty(D))   { badMetrics.push("D"); }
  // if (!CVSS31.Weight.R.hasOwnProperty(G)) { badMetrics.push("G"); }
  // if (!CVSS31.Weight.R.hasOwnProperty(E))   { badMetrics.push("E"); }
  // if (!CVSS31.Weight.R.hasOwnProperty(V))     { badMetrics.push("V"); }

  if (badMetrics.length > 0) {
    return { success: false, errorType: "UnknownMetricValue", errorMetrics: badMetrics };
  }



  // GATHER WEIGHTS FOR ALL METRICS

  var metricWeightU  = CVSS31.Weight.R.U    [U];
  var metricWeightD  = CVSS31.Weight.R.D    [D];
  var metricWeightG  = CVSS31.Weight.R.G    [G];  // PR depends on the value of Scope (S).
  var metricWeightE  = CVSS31.Weight.R.E    [E];
  var metricWeightV  = CVSS31.Weight.R.V    [V];


  // CALCULATE THE CVSS BASE SCORE

  var reifegrad;

  // since only one option can be choosen its a discrete value between 0 and 4
  reifegrad = metricWeightU + metricWeightD + metricWeightG + metricWeightE + metricWeightV;
  
  // CONSTRUCT THE VECTOR STRING
  var vectorString =
    "/U:" + U +
    "/D:" + D +
    "/G:" + G +
    "/E:" + E +
    "/V:" + V;

  // Return an object containing the scores for all three metric groups, and an overall vector string.
  // Sub-formula values are also included.

  return {
    success: true,

    reifegrad: reifegrad,

    vectorString: vectorString
  };
};




/* ** CVSS31.calculateCVSSFromVector **
 *
 * Takes Base, Temporal and Environmental metric values as a single string in the Vector String format defined
 * in the CVSS v3.1 standard definition of the Vector String.
 *
 * Returns Base, Temporal and Environmental scores, severity ratings, and an overall Vector String. All Base metrics
 * are required to generate this output. All Temporal and Environmental metric values are optional. Any that are not
 * passed default to "X" ("Not Defined").
 *
 * See the comment for the CVSS31.calculateCVSSFromMetrics function for details on the function output. In addition to
 * the error conditions listed for that function, this function can also return:
 *   "MalformedVectorString", if the Vector String passed does not conform to the format in the standard; or
 *   "MultipleDefinitionsOfMetric", if the Vector String is well formed but defines the same metric (or metrics),
 *                                  more than once.
 */
CVSS31.calculateCVSSFromVector = function ( vectorString ) {

  var metricValues = {
    U:  undefined, D:  undefined, G:  undefined, E:  undefined, V:  undefined
  };

  // If input validation fails, this array is populated with strings indicating which metrics failed validation.
  var badMetrics = [];
  var metricNameValue = vectorString.substring(CVSS31.CVSSVersionIdentifier.length).split("/");

  for (var i in metricNameValue) {
    if (metricNameValue.hasOwnProperty(i)) {

      var singleMetric = metricNameValue[i].split(":");

      if (typeof metricValues[singleMetric[0]] === "undefined") {
        metricValues[singleMetric[0]] = singleMetric[1];
      } else {
        badMetrics.push(singleMetric[0]);
      }
    }
  }

  if (badMetrics.length > 0) {
    return { success: false, errorType: "MultipleDefinitionsOfMetric", errorMetrics: badMetrics };
  }

  return CVSS31.calculateCVSSFromMetrics (
    metricValues.U,  metricValues.D,  metricValues.G,  metricValues.E,  metricValues.V);
};


/* ** CVSS31.severityRating **
 *
 * Given a CVSS score, returns the name of the severity rating as defined in the CVSS standard.
 * The input needs to be a number between 0.0 to 4.0, to one decimal place of precision.
 *
 * The following error values may be returned instead of a severity rating name:
 *   NaN (JavaScript "Not a Number") - if the input is not a number.
 *   undefined - if the input is a number that is not within the range of any defined severity rating.
 */
CVSS31.severityRating = function (score) {
  var severityRatingLength = CVSS31.severityRatings.length;

  var validatedScore = Number(score);

  if (isNaN(validatedScore)) {
    return validatedScore;
  }

  for (var i = 0; i < severityRatingLength; i++) {
    if (score = CVSS31.severityRatings[i].top) {
      return CVSS31.severityRatings[i].name;
    }
  }

  return undefined;
};



///////////////////////////////////////////////////////////////////////////
// DATA AND FUNCTIONS FOR CREATING AN XML REPRESENTATION OF A CVSS SCORE //
///////////////////////////////////////////////////////////////////////////

// A mapping between abbreviated metric values and the string used in the XML representation.
// For example, a Remediation Level (RL) abbreviated metric value of "W" maps to "WORKAROUND".
// For brevity, every Base metric shares its definition with its equivalent Environmental metric. This is possible
// because the metric values are same between these groups, except that the latter have an additional metric value
// of "NOT_DEFINED".

CVSS31.XML_MetricNames = {
  E:    { X: "NOT_DEFINED", U: "UNPROVEN",     P: "PROOF_OF_CONCEPT",  F: "FUNCTIONAL",  H: "HIGH"},
  RL:   { X: "NOT_DEFINED", O: "OFFICIAL_FIX", T: "TEMPORARY_FIX",     W: "WORKAROUND",  U: "UNAVAILABLE"},
  RC:   { X: "NOT_DEFINED", U: "UNKNOWN",      R: "REASONABLE",        C: "CONFIRMED"},

  CIAR: { X: "NOT_DEFINED", L: "LOW",              M: "MEDIUM", H: "HIGH"},         // CR, IR and AR use the same values
  MAV:  { N: "NETWORK",     A: "ADJACENT_NETWORK", L: "LOCAL",  P: "PHYSICAL", X: "NOT_DEFINED" },
  MAC:  { H: "HIGH",        L: "LOW",              X: "NOT_DEFINED" },
  MPR:  { N: "NONE",        L: "LOW",              H: "HIGH",   X: "NOT_DEFINED" },
  MUI:  { N: "NONE",        R: "REQUIRED",         X: "NOT_DEFINED" },
  MS:   { U: "UNCHANGED",   C: "CHANGED",          X: "NOT_DEFINED" },
  MCIA: { N: "NONE",        L: "LOW",              H: "HIGH",   X: "NOT_DEFINED" }  // C, I and A use the same values
};



/* ** CVSS31.generateXMLFromMetrics **
 *
 * Takes Base, Temporal and Environmental metric values as individual parameters. Their values are in the short format
 * defined in the CVSS v3.1 standard definition of the Vector String. For example, the AttackComplexity parameter
 * should be either "H" or "L".
 *
 * Returns a single string containing the metric values in XML form. All Base metrics are required to generate this
 * output. All Temporal and Environmental metric values are optional. Any that are not passed will be represented in
 * the XML as NOT_DEFINED. The function returns a string for simplicity. It is arguably better to return the XML as
 * a DOM object, but at the time of writing this leads to complexity due to older browsers using different JavaScript
 * interfaces to do this. Also for simplicity, all Temporal and Environmental metrics are included in the string,
 * even though those with a value of "Not Defined" do not need to be included.
 *
 * The output of this function is an object which always has a property named "success".
 *
 * If no errors are encountered, success is Boolean "true", and the "xmlString" property contains the XML string
 * representation.
 *
 * If errors are encountered, success is Boolean "false", and other properties are defined as per the
 * CVSS31.calculateCVSSFromMetrics function. Refer to the comment for that function for more details.
 */
//--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
CVSS31.generateXMLFromMetrics = function (
  Unvollständig, Durchgeführt, Gesteuert, Etabliert, Vorhersagbar) {

  // A string containing the XML we wish to output, with placeholders for the CVSS metrics we will substitute for
  // their values, based on the inputs passed to this function.
  var xmlTemplate =
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<cvssv3.1 xmlns="https://www.first.org/cvss/cvss-v3.1.xsd"\n' +
    '  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"\n' +
    '  xsi:schemaLocation="https://www.first.org/cvss/cvss-v3.1.xsd https://www.first.org/cvss/cvss-v3.1.xsd"\n' +
    '  >\n' +
    '\n' +
    '  <base_metrics>\n' +
    '    <attack-vector>__AttackVector__</attack-vector>\n' +
    '    <attack-complexity>__AttackComplexity__</attack-complexity>\n' +
    '    <privileges-required>__PrivilegesRequired__</privileges-required>\n' +
    '    <user-interaction>__UserInteraction__</user-interaction>\n' +
    '    <scope>__Scope__</scope>\n' +
    '    <confidentiality-impact>__Confidentiality__</confidentiality-impact>\n' +
    '    <integrity-impact>__Integrity__</integrity-impact>\n' +
    '    <availability-impact>__Availability__</availability-impact>\n' +
    '    <base-score>__BaseScore__</base-score>\n' +
    '    <base-severity>__BaseSeverityRating__</base-severity>\n' +
    '  </base_metrics>\n' +
    '\n' +
    '  <temporal_metrics>\n' +
    '    <exploit-code-maturity>__ExploitCodeMaturity__</exploit-code-maturity>\n' +
    '    <remediation-level>__RemediationLevel__</remediation-level>\n' +
    '    <report-confidence>__ReportConfidence__</report-confidence>\n' +
    '    <temporal-score>__TemporalScore__</temporal-score>\n' +
    '    <temporal-severity>__TemporalSeverityRating__</temporal-severity>\n' +
    '  </temporal_metrics>\n' +
    '\n' +
    '  <environmental_metrics>\n' +
    '    <confidentiality-requirement>__ConfidentialityRequirement__</confidentiality-requirement>\n' +
    '    <integrity-requirement>__IntegrityRequirement__</integrity-requirement>\n' +
    '    <availability-requirement>__AvailabilityRequirement__</availability-requirement>\n' +
    '    <modified-attack-vector>__ModifiedAttackVector__</modified-attack-vector>\n' +
    '    <modified-attack-complexity>__ModifiedAttackComplexity__</modified-attack-complexity>\n' +
    '    <modified-privileges-required>__ModifiedPrivilegesRequired__</modified-privileges-required>\n' +
    '    <modified-user-interaction>__ModifiedUserInteraction__</modified-user-interaction>\n' +
    '    <modified-scope>__ModifiedScope__</modified-scope>\n' +
    '    <modified-confidentiality-impact>__ModifiedConfidentiality__</modified-confidentiality-impact>\n' +
    '    <modified-integrity-impact>__ModifiedIntegrity__</modified-integrity-impact>\n' +
    '    <modified-availability-impact>__ModifiedAvailability__</modified-availability-impact>\n' +
    '    <environmental-score>__EnvironmentalScore__</environmental-score>\n' +
    '    <environmental-severity>__EnvironmentalSeverityRating__</environmental-severity>\n' +
    '  </environmental_metrics>\n' +
    '\n' +
    '</cvssv3.1>\n';


  // Call CVSS31.calculateCVSSFromMetrics to validate all the parameters and generate scores and severity ratings.
  // If that function returns an error, immediately return it to the caller of this function.
  // var result = CVSS31.calculateCVSSFromMetrics (
  //   AttackVector, AttackComplexity, PrivilegesRequired, UserInteraction, Scope, Confidentiality, Integrity, Availability,
  //   ExploitCodeMaturity, RemediationLevel, ReportConfidence,
  //   ConfidentialityRequirement, IntegrityRequirement, AvailabilityRequirement,
  //   ModifiedAttackVector, ModifiedAttackComplexity, ModifiedPrivilegesRequired, ModifiedUserInteraction, ModifiedScope,
  //   ModifiedConfidentiality, ModifiedIntegrity, ModifiedAvailability);

    var result = CVSS31.calculateCVSSFromMetrics(
      Unvollständig, Durchgeführt, Gesteuert, Etabliert, Vorhersagbar)

  if (result.success !== true) {
    return result;
  }

  var xmlOutput = xmlTemplate;
  xmlOutput = xmlOutput.replace ("__Unvollständig__",   CVSS31.XML_MetricNames["U"][Unvollständig]);
  xmlOutput = xmlOutput.replace ("__Durchgeführt__",    CVSS31.XML_MetricNames["D"][Durchgeführt]);
  xmlOutput = xmlOutput.replace ("__Gesteuert__",       CVSS31.XML_MetricNames["G"][Gesteuert]);
  xmlOutput = xmlOutput.replace ("__Etabliert__",       CVSS31.XML_MetricNames["E"][Etabliert]);
  xmlOutput = xmlOutput.replace ("__Vorhersagbar__",    CVSS31.XML_MetricNames["V"][Vorhersagbar]);
  xmlOutput = xmlOutput.replace ("__Reifegrad__",           result.reifegrad);

  return { success: true, xmlString: xmlOutput };
};



/* ** CVSS31.generateXMLFromVector **
 *
 * Takes Base, Temporal and Environmental metric values as a single string in the Vector String format defined
 * in the CVSS v3.1 standard definition of the Vector String.
 *
 * Returns an XML string representation of this input. See the comment for CVSS31.generateXMLFromMetrics for more
 * detail on inputs, return values and errors. In addition to the error conditions listed for that function, this
 * function can also return:
 *   "MalformedVectorString", if the Vector String passed is does not conform to the format in the standard; or
 *   "MultipleDefinitionsOfMetric", if the Vector String is well formed but defines the same metric (or metrics),
 *                                  more than once.
 */
CVSS31.generateXMLFromVector = function ( vectorString ) {

  var metricValues = {
    AV:  undefined, AC:  undefined, PR:  undefined, UI:  undefined, S:  undefined,
    C:   undefined, I:   undefined, A:   undefined,
    E:   undefined, RL:  undefined, RC:  undefined,
    CR:  undefined, IR:  undefined, AR:  undefined,
    MAV: undefined, MAC: undefined, MPR: undefined, MUI: undefined, MS: undefined,
    MC:  undefined, MI:  undefined, MA:  undefined
  };

  // If input validation fails, this array is populated with strings indicating which metrics failed validation.
  var badMetrics = [];

  if (!CVSS31.vectorStringRegex_31.test(vectorString)) {
    return { success: false, errorType: "MalformedVectorString" };
  }

  var metricNameValue = vectorString.substring(CVSS31.CVSSVersionIdentifier.length).split("/");

  for (var i in metricNameValue) {
    if (metricNameValue.hasOwnProperty(i)) {

      var singleMetric = metricNameValue[i].split(":");

      if (typeof metricValues[singleMetric[0]] === "undefined") {
        metricValues[singleMetric[0]] = singleMetric[1];
      } else {
        badMetrics.push(singleMetric[0]);
      }
    }
  }

  if (badMetrics.length > 0) {
    return { success: false, errorType: "MultipleDefinitionsOfMetric", errorMetrics: badMetrics };
  }

  return CVSS31.generateXMLFromMetrics (
    metricValues.AV,  metricValues.AC,  metricValues.PR,  metricValues.UI,  metricValues.S,
    metricValues.C,   metricValues.I,   metricValues.A,
    metricValues.E,   metricValues.RL,  metricValues.RC,
    metricValues.CR,  metricValues.IR,  metricValues.AR,
    metricValues.MAV, metricValues.MAC, metricValues.MPR, metricValues.MUI, metricValues.MS,
    metricValues.MC,  metricValues.MI,  metricValues.MA);
};

module.exports = CVSS31;