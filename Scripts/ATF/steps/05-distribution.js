// ATF step 5: report all five actual/expected percentages, results and breach deltas.
(function(outputs, steps, stepResult, assertEqual) {
    var result = new sn_vul.VRRiskDataHealth().run('distribution');
    stepResult.setOutputMessage(result.message);
    assertEqual({ name: 'VR risk health rating distribution', shouldbe: true, value: result.passed });
    return result.passed;
})(outputs, steps, stepResult, assertEqual);
