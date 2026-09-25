// ATF step 4: verify every valid score maps to its configured risk rating.
(function(outputs, steps, stepResult, assertEqual) {
    var result = new VRRiskDataHealth().run('consistency');
    stepResult.setOutputMessage(result.message);
    assertEqual({ name: 'VR risk health score/rating consistency', shouldbe: true, value: result.passed });
    return result.passed;
})(outputs, steps, stepResult, assertEqual);
